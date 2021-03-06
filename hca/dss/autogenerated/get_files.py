"""This file is autogenerated according to HCA api spec. Don't modify."""
from ..added_command import AddedCommand


class GetFiles(AddedCommand):
    """Class containing info to reach the get endpoint of files."""

    @classmethod
    def _get_base_url(cls):
        return "https://dss.dev.data.humancellatlas.org/v1"

    @classmethod
    def _get_endpoint_info(cls):
        return {u'description': u'Given a file UUID, return the latest version of that file.  If the version is provided, that version of the file\nis returned instead.\n\nHeaders will contain the data store metadata for the file.\n\nThis endpoint will do a HTTP redirect to another HTTP endpoint with the file contents.\n', u'body_params': {}, u'positional': [{u'description': u'A RFC4122-compliant ID for the file.', u'format': None, u'pattern': u'[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}', u'required': True, u'argument': u'uuid', u'required_for': [u'/files/{uuid}'], u'type': u'string'}], u'seen': False, u'requires_auth': False, u'options': {u'replica': {u'hierarchy': [u'replica'], u'in': u'query', u'description': u'Replica to fetch from.', u'required_for': [u'/files/{uuid}'], u'format': None, u'pattern': None, u'array': False, u'required': True, u'type': u'string', u'metavar': None}, u'version': {u'hierarchy': [u'version'], u'in': u'query', u'description': u'Timestamp of file creation in RFC3339.  If this is not provided, the latest version is returned.', u'required_for': [], u'format': u'date-time', u'pattern': None, u'array': False, u'required': False, u'type': u'string', u'metavar': None}}}
