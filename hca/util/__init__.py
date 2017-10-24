"""
This file contains utility functions for the DCP CLI.
"""

import os, sys, argparse, yaml, types, collections, typing, json, errno, logging

try:
    from inspect import signature, Signature, Parameter
except ImportError:
    from funcsigs import signature, Signature, Parameter

import requests, CommonMark, tweak
from requests_oauthlib import OAuth2Session

class SwaggerClientConfig(tweak.Config):
    default_config_file = os.path.join(os.path.dirname(__file__), "default_config.json")
    @property
    def config_files(self):
        return [self.default_config_file] + tweak.Config.config_files.fget(self)

    @property
    def user_config_dir(self):
        return os.path.join(self._user_config_home, self._name)


_pagination_docstring = """
.. admonition:: Pagination

 This method supports pagination. Use ``{client_name}.{method_name}.iterate(**kwargs)`` to create a generator that yields
 all results, making multiple requests over the wire if necessary:

 .. code-block:: python

   for result in {client_name}.{method_name}.iterate(**kwargs):
       ...

 The keyword arguments for ``{client_name}.{method_name}.iterate()`` are identical to the arguments for
 ``{client_name}.{method_name}()`` listed here.
"""

class SwaggerClient:
    _swagger_spec = None
    _session = None
    _authenticated_session = None
    scheme = "https"
    type_map = {
        "string": str,
        "number": float,
        "integer": int,
        "boolean": bool,
        "array": typing.List,
        "object": typing.Mapping
    }
    def __new__(cls, config=None, **session_kwargs):
        print("In new")
        self = super(SwaggerClient, cls).__new__(cls)
        self.config = config or SwaggerClientConfig("dscli2")

        cls.__doc__ = self._md2rst(self.swagger_spec["info"]["description"])
        self.methods = {}
        self.http_paths = collections.defaultdict(dict)
        self.host = "{scheme}://{host}{base}".format(scheme=self.scheme,
                                                     host=self.swagger_spec["host"],
                                                     base=self.swagger_spec["basePath"])
        for http_path, path_data in self.swagger_spec["paths"].items():
            for http_method, method_data in path_data.items():
                self._build_client_method(http_method, http_path, method_data)
        print("End new")
        return self

    @property
    def swagger_spec(self):
        if not self._swagger_spec:
            if "swagger_filename" not in self.config:
                try:
                    os.makedirs(self.config.user_config_dir)
                except OSError as e:
                    if not (e.errno == errno.EEXIST and os.path.isdir(self.config.user_config_dir)):
                        raise
                self.config.swagger_filename = os.path.join(self.config.user_config_dir,
                                                            self.__class__.__name__ + ".swagger.yml")
                with open(self.config.swagger_filename, "wb") as fh:
                    fh.write(requests.get(self.config.swagger_url).content)
            swagger_filename = self.config.swagger_filename
            if not swagger_filename.startswith("/"):
                swagger_filename = os.path.join(os.path.dirname(__file__), swagger_filename)
            with open(swagger_filename) as fh:
                SwaggerClient._swagger_spec = yaml.load(fh.read())
        return self._swagger_spec

    @property
    def application_secrets(self):
        if "application_secrets" not in self.config:
            app_secrets_url = "https://{}/internal/application_secrets".format(self._swagger_spec["host"])
            self.config.application_secrets = requests.get(app_secrets_url).json()
        return self.config.application_secrets

    def get_session(self):
        if self._session is None:
            self._session = requests.Session()
            self._session.headers.update({"User-Agent": self.__class__.__name__})
        return self._session

    def logout(self, entry_point=None):
        try:
            del self.config["oauth2_token"]
        except KeyError:
            pass

    def login(self, entry_point=None):
        scopes = ["https://www.googleapis.com/auth/userinfo.email"]
        from google_auth_oauthlib.flow import InstalledAppFlow
        flow = InstalledAppFlow.from_client_config(self.application_secrets, scopes=scopes)
        credentials = flow.run_local_server()
        # TODO: (akislyuk) test token autorefresh on expiration
        self.config.oauth2_token = dict(access_token=credentials.token,
                                        refresh_token=credentials.refresh_token,
                                        id_token=credentials.id_token,
                                        expires_at="-1",
                                        token_type="Bearer")

    def _get_oauth_token_from_service_account_credentials(self):
        scopes = ["https://www.googleapis.com/auth/userinfo.email"]
        assert 'GOOGLE_APPLICATION_CREDENTIALS' in os.environ
        from google.auth.transport.requests import Request as GoogleAuthRequest
        from google.oauth2.service_account import Credentials as ServiceAccountCredentials
        logging.info("Found GOOGLE_APPLICATION_CREDENTIALS environment variable. "
                     "Using service account credentials for authentication.")
        service_account_credentials_filename = os.environ['GOOGLE_APPLICATION_CREDENTIALS']

        if not os.path.isfile(service_account_credentials_filename):
            msg = 'File "{}" referenced by the GOOGLE_APPLICATION_CREDENTIALS environment variable does not exist'
            raise Exception(msg.format(service_account_credentials_filename))

        credentials = ServiceAccountCredentials.from_service_account_file(service_account_credentials_filename,
                                                                          scopes=scopes)
        r = GoogleAuthRequest()
        credentials.refresh(r)
        r.session.close()
        return credentials.token, credentials.expiry

    def get_authenticated_session(self):
        if self._authenticated_session is None:
            oauth2_client_data = self.application_secrets["installed"]
            if 'GOOGLE_APPLICATION_CREDENTIALS' in os.environ:
                token, expires_at = self._get_oauth_token_from_service_account_credentials()
                # TODO: (akislyuk) figure out the right strategy for persisting the service account oauth2 token
                self._authenticated_session = OAuth2Session(client_id=oauth2_client_data["client_id"],
                                                            token=dict(access_token=token))
            else:
                if "oauth2_token" not in self.config:
                    raise Exception('Please configure {prog} authentication credentials using "{prog} login" '
                                    'or set the GOOGLE_APPLICATION_CREDENTIALS environment variable')
                self._authenticated_session = OAuth2Session(
                    client_id=oauth2_client_data["client_id"],
                    token=self.config.oauth2_token,
                    auto_refresh_url=oauth2_client_data["token_uri"],
                    auto_refresh_kwargs=dict(client_id=oauth2_client_data["client_id"],
                                             client_secret=oauth2_client_data["client_secret"]),
                    token_updater=self._save_auth_token_refresh_result
                )
            self._authenticated_session.headers.update({"User-Agent": self.__class__.__name__})
        return self._authenticated_session

    def _save_auth_token_refresh_result(self, result):
        self.config.oauth2_token = result

    def _build_client_method(self, http_method, http_path, method_data):
        method_name_parts = [http_method] + [p for p in http_path.split("/")[1:] if not p.startswith("{")]
        method_name = "_".join(method_name_parts)
        method_args = collections.OrderedDict()
        parameters = {p["name"]: p for p in method_data["parameters"]}

        path_parameters = [p_name for p_name, p_data in parameters.items() if p_data["in"] == "path"]
        self.http_paths[method_name][frozenset(path_parameters)] = http_path

        body_props = {}
        for parameter in parameters.values():
            if parameter["in"] == "body":
                for prop_name, prop_data in parameter["schema"]["properties"].items():
                    anno = self.type_map[prop_data["type"]]
                    if prop_name not in parameter["schema"]["required"]:
                        anno = typing.Optional[anno]
                    param = Parameter(prop_name, Parameter.POSITIONAL_OR_KEYWORD, default=prop_data.get("default"),
                                      annotation=anno)
                    method_args[prop_name] = dict(param=param, doc=prop_data.get("description"),
                                                  choices=parameter.get("enum"))
                    body_props[prop_name] = parameter["schema"]
            else:
                anno = str if parameter.get("required") else typing.Optional[str]
                param = Parameter(parameter["name"], Parameter.POSITIONAL_OR_KEYWORD, default=parameter.get("default"),
                                  annotation=anno)
                method_args[parameter["name"]] = dict(param=param, doc=parameter.get("description"),
                                                      choices=parameter.get("enum"))

        method_supports_pagination = True if str(requests.codes.partial) in method_data["responses"] else False

        class ClientMethodFactory:
            def _request(factory, req_args, url=None):
                supplied_path_params = [p for p in req_args if p in path_parameters and req_args[p] is not None]
                if url is None:
                    url = self.host + self.http_paths[method_name][frozenset(supplied_path_params)]
                    url = url.format(**req_args)
                print("Will request", http_method, url, "with", req_args)
                query = {k: v for k, v in req_args.items() if parameters.get(k, {}).get("in") == "query" and v is not None}
                body = {k: v for k, v in req_args.items() if k in body_props and v is not None}
                session = self.get_authenticated_session() if "security" in method_data else self.get_session()

                # TODO: (akislyuk) if using service account credentials, use manual refresh here
                res = session.request(http_method, url, params=query, json=body if body_props else None)
                if res.status_code >= 400:
                    raise Exception(res.content.decode())
                return res

            def __call__(factory, client, entry_point=None, **kwargs):
                return factory._request(kwargs).json()

            if method_supports_pagination:
                def iterate(factory, entry_point=None, **kwargs):
                    page = None
                    while page is None or page.links.get("next", {}).get("url"):
                        page = factory._request(kwargs, url=page.links["next"]["url"] if page else None)
                        for result in page.json()["results"]:
                            yield result

        client_method = ClientMethodFactory()
        client_method.__name__ = method_name
        client_method.__qualname__ = self.__class__.__name__ + "." + method_name

        params = [Parameter("factory", Parameter.POSITIONAL_OR_KEYWORD),
                  Parameter("client", Parameter.POSITIONAL_OR_KEYWORD)]
        params += [v["param"] for k, v in method_args.items() if not k.startswith("_")]
        client_method.__signature__ = signature(client_method).replace(parameters=params)
        docstring = method_data["summary"] + "\n\n"

        if method_supports_pagination:
            docstring += _pagination_docstring.format(client_name=self.__class__.__name__, method_name=method_name)

        for param in method_args:
            if not param.startswith("_"):
                param_doc = self._md2rst(method_args[param]["doc"] or "")
                docstring += ":param {}: {}\n".format(param, param_doc.replace("\n", " "))
                docstring += ":type {}: {}\n".format(param, method_args[param]["param"].annotation)
        docstring += "\n\n" + self._md2rst(method_data["description"])
        client_method.__doc__ = docstring

        setattr(self.__class__, method_name, types.MethodType(client_method, SwaggerClient))
        self.methods[method_name] = dict(method_data, entry_point=getattr(self, method_name),
                                         signature=client_method.__signature__, args=method_args)

    def build_argparse_subparsers(self, parser):
        subparsers = parser.add_subparsers()
        for method_name, method_data in self.methods.items():
            subcommand_name = method_name.replace("_", "-")
            subparser = subparsers.add_parser(subcommand_name, help=method_data.get("summary"),
                                              description=method_data.get("description"))
            for param_name, param in method_data["signature"].parameters.items():
                if param_name in {"client", "factory"}:
                    continue
                print(method_name, param_name, param.annotation)
                nargs = "*" if param.annotation == typing.List else None
                argparse_type = json.loads if param.annotation in {typing.List, typing.Mapping} else param.annotation
                subparser.add_argument("--" + param_name.replace("_", "-").replace("/", "-"), dest=param_name,
                                       type=argparse_type, nargs=nargs, help=method_data["args"][param_name]["doc"],
                                       choices=method_data["args"][param_name]["choices"])
            subparser.set_defaults(entry_point=method_data["entry_point"])
        login_subparser = subparsers.add_parser("login", help="FIXME", description="FIXME FIXME")
        login_subparser.set_defaults(entry_point=self.login)
        logout_subparser = subparsers.add_parser("logout", help="FIXME", description="FIXME FIXME")
        logout_subparser.set_defaults(entry_point=self.logout)

    def _md2rst(self, docstring):
        parser = CommonMark.Parser()
        ast = parser.parse(docstring)
        renderer = CommonMark.ReStructuredTextRenderer()
        return renderer.render(ast)

#client = SwaggerClient()
#parser = argparse.ArgumentParser(description=client.__doc__)
#client.build_argparse_subparsers(parser)
#help(client.get_subscriptions)
#print(client.get_subscriptions(replica="aws"))
#print(client.post_search(replica="aws", es_query={}))
#for result in client.post_search.iterate(replica="aws", es_query={}):
#    print(result)
#args = parser.parse_args()
#print(args)
#print(args.entry_point(**vars(args)))
