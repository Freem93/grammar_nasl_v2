#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45477);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/26 18:40:45 $");

  script_name(english:"LDAP Group Enumeration");
  script_summary(english:"Retrieves the list of groups via LDAP.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to get the list of groups on the remote LDAP server.");
  script_set_attribute(attribute:"description", value:
"By using the search base gathered by plugin ID 25701, Nessus was able
to enumerate the list of groups in the remote LDAP directory.");
  script_set_attribute(attribute:"solution", value:
"Configure the LDAP server to require authentication.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("ldap_search.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("kerberos_func.inc");
include("ldap_func.inc");

port = get_service(svc:"ldap", exit_on_fail:TRUE);

list = get_kb_list('LDAP/'+port+'/namingContexts');
if (isnull(list)) exit(0, 'The LDAP/'+port+'/namingContexts KB list is missing.');
list = make_list(list);

obj = NULL;
foreach namingcontext (list)
{
  # Look for the DC= elements
  if ('dc=' >< namingcontext)
  {
    ret = ldap_extract_dc(namingcontext:namingcontext);
    obj = ret['obj'];
    break;
  }
}

if (isnull(obj)) exit(1, "Couldn't extract the domain information from the namingcontexts for the LDAP server listening on port "+port+".");

soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open socket on port "+port+".");

ldap_init(socket:soc);

search_filters = make_nested_list(
  make_array(
    "object", "cn=users," + obj,
    "filter", "group",
    "scope", 0x01
  ),
  make_array(
    "object", obj,
    "filter", "posixGroup",
    "scope", 0x02
  )
);

report = NULL;
groups = make_array();
foreach search_val (search_filters)
{
	filters = make_list();
	filter = make_array();
	filter["left"] = 'objectclass';
	filter["conditional"] = LDAP_FILTER_EQUAL;
	filter["right"] = search_val["filter"];
	filters[0] = filter;
	search = ldap_search_request(object:search_val["object"], filter:filters, scope:search_val["scope"]);
	ret = ldap_request_sendrecv(data:search);

	repeat {
	  if (isnull(ret) || ret[0] != LDAP_SEARCH_RES_ENTRY)
		break;
	  data = ldap_parse_search_object_name(data:ret[1]);
          groups[data - strcat(",", obj)] = 1;
	  ret = ldap_recv_next();
	} until (isnull(ret));
}

count = 0;
foreach group (keys(groups))
{
  count++;
  set_kb_item(name:"LDAP/Groups/"+count, value:group);
  report += string ("   |  ", group, "\n");
}

if (count > 0) set_kb_item(name:"LDAP/Groups/count", value:count);

if ( strlen(report) > 0 ) 
{
 if (report_verbosity > 0)
 {
  report = string ("[+]-groups:\n") + report;
  security_note(port:port, extra:report);
 }
 else security_note(port);
}

