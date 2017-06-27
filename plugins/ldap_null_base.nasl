#
# (C) Tenable Network Security, Inc.
#
# Changes by Tenable:
# - Revised plugin title, family change (9/1/09)
# - Rewritten plugin (8/31/11)
#

include("compat.inc");

if(description)
{
  script_id(10722);
  script_version ("$Revision: 1.23 $");
  script_cvs_date("$Date: 2014/10/24 18:56:58 $");

  script_name(english:"LDAP NULL BASE Search Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote LDAP server may disclose sensitive information.");
 script_set_attribute(attribute:"description", value:
"The remote LDAP server supports search requests with a NULL, or empty,
base object. This allows information to be retrieved without any prior
knowledge of the directory structure. Coupled with a NULL BIND, an
anonymous user may be able to query your LDAP server using a tool such
as 'LdapMiner'. 

Note that there are valid reasons to allow queries with a NULL base.
For example, it is required in version 3 of the LDAP protocol to
provide access to the root DSA-Specific Entry (DSE), with information
about the supported naming context, authentication types, and the
like. It also means that legitimate users can find information in the
directory without any prior knowledge of its structure. As such, this
finding may be a false-positive." );
 script_set_attribute(attribute:"solution", value:
"If the remote LDAP server supports a version of the LDAP protocol
before v3, consider whether to disable NULL BASE queries on your LDAP
server." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/08/13");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/837964");
 script_end_attributes();

  script_summary(english:"Check for LDAP null base");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}

include("kerberos_func.inc");
include("ldap_func.inc");

port = get_kb_item("Services/ldap");
if (!port) port = 389;
if ( ! get_port_state(port) ) exit(0, "Port is closed");
soc = open_sock_tcp(port);
if ( ! soc ) exit(0, "Port is closed");
ldap_init(socket:soc);

bind = 
        der_encode_int(i:2)                 +  # LDAP version
        der_encode_octet_string(string:"")  +  # name
        der_encode(tag:LDAP_AUTHENTICATION_TAG, data:"");
bind = ldap_request(code:LDAP_BIND_REQUEST, data:bind);

search = 
        der_encode_octet_string (string:"") +
        der_encode_enumerated(e:"") +
        der_encode_enumerated(e:0) +
        der_encode_int(i:0) +
        der_encode_int(i:0) +
        der_encode_boolean(b:FALSE) +
        der_encode_filter(filter:"objectclass") +
        der_encode_list(list:"");

ret = ldap_request_sendrecv(data:bind);
if (isnull(ret) || ret[0] != LDAP_BIND_RESPONSE)
  exit(1, "Unexpected reponse to the bind request on port " + port);

data = ldap_parse_bind_response(data:ret[1]);
if (isnull(data) || data[0] != 0)
{
  close(soc);
  exit(1, "ldap_parse_bind_response() failed for port " + port);
}

search = ldap_request(code:LDAP_SEARCH_REQUEST, data:search);
ret = ldap_request_sendrecv(data:search);
if ( isnull(ret) || ret[0] != LDAP_SEARCH_RES_ENTRY ) 
{
 close(soc);
 exit(1, "LDAP search response is not vulnerable");
}
data = ldap_parse_search_entry(data:ret[1]);
close(soc);

# http://support.microsoft.com/kb/837964
# http://www.cse.ohio-state.edu/cgi-bin/rfc/rfc2251.html
acceptable_entries = make_array(tolower("currentTime"), 1,
				tolower("subschemaSubentry"), 1,
				tolower("dsServiceName"), 1,
				tolower("namingContexts"), 1,
				tolower("defaultNamingContext"), 1,
				tolower("schemaNamingContext"), 1,
				tolower("configurationNamingContext"), 1,
				tolower("rootDomainNamingContext"), 1,
				tolower("supportedControl"), 1,
				tolower("supportedLDAPVersion"), 1,
				tolower("supportedLDAPPolicies"), 1,
				tolower("highestCommittedUSN"), 1,
				tolower("supportedSASLMechanisms"), 1,
				tolower("dnsHostName"), 1,
				tolower("ldapServiceName"), 1,
				tolower("serverName"), 1,
				tolower("supportedCapabilities"), 1,
				tolower("isSynchronized"), 1,
				tolower("domainFunctionality"), 1,
				tolower("domainControllerFunctionality"), 1,
				tolower("forestFunctionality"), 1,
				tolower("isGlobalCatalogReady"), 1);

report = '';
for ( i = 0 ; i < max_index(data); i ++ )
{
 if ( !isnull(acceptable_entries[tolower(data[i][0])]) ) continue;
 report += strcat(data[i][0], ": ");
 for ( j = 0 ; j < max_index(data[i][1]) ; j ++ )
 {
  if ( j > 0 ) report += ", ";
  report += data[i][1][j];
 }
 report += '\n';
}

if ( strlen(report) > 0 )
  security_warning(port:port, extra:'The following non-RFC mandatory information could be gathered :\n' + report);
