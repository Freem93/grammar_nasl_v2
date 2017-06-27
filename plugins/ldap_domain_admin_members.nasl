#
# (C) Tenable Network Security, Inc.
#
# @PREFERENCES@

include("compat.inc");

if (description)
{
  script_id(58038);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/26 18:40:45 $");

  script_name(english:"LDAP 'Domain Admins' Group Membership Enumeration");
  script_summary(english:"Retrieves the list of members of the 'Domain Admins' group.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to list the members of the 'Domain Admins' group on
the remote LDAP server.");
  script_set_attribute(attribute:"description", value:
"By using the search base gathered by plugin ID 25701 and the supplied
credentials, Nessus was able to enumerate the list of members of the
'Domain Admins' group in the remote LDAP directory.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("ldap_search.nasl");
  script_require_ports("Services/ldap", 389);

  script_add_preference(name:"LDAP user : ", type:"entry", value:"");
  script_add_preference(name:"LDAP password : ", type:"password", value:"");
  script_add_preference(name:"Max results : ", type:"entry", value:"1000");

  exit(0);
}

include("global_settings.inc");
include("kerberos_func.inc");
include("ldap_func.inc");
include("misc_func.inc");

ldap_user = script_get_preference("LDAP user : ");
ldap_pass = script_get_preference("LDAP password : ");
max_results = script_get_preference("Max results : ");

if (!max_results) max_results = 1000;
else
{
  max_results = int(max_results);
  if (max_results <= 0) max_results = 1000;
}

port = get_service(svc:'ldap', exit_on_fail:TRUE);

list = get_kb_list('LDAP/'+port+'/namingContexts');
if (isnull(list)) exit(0, 'The LDAP/'+port+'/namingContexts KB list is missing.');
list = make_list(list);

domain = NULL;
domain_obj = NULL;
foreach namingcontext (list)
{
  # Look for the DC= elements, but leave out DomainDnsZones and ForestDnsZones
  ret = ldap_extract_dc(namingcontext:namingcontext);
  if (ret['obj'])
  {
    domain_obj = ret['obj'];
    domain = ret['domain'];
    break;
  }
}

if (isnull(domain_obj)) exit(1, "Couldn't extract the domain information from the namingcontexts for the LDAP server listening on port "+port+".");

# From the CN=Schema, we only want the DC components
group = 'Domain Admins';
obj = 'CN='+group+',CN=Users,' + domain_obj;

# In some cases the user name needs to be in the form of
# user@domain.  If the username doesn't contain @domain,
# append it to the username
domain = '@' + domain;
if ('@' >!< ldap_user) ldap_user += domain;

# Initiate the ldap connection
soc = open_sock_tcp(port);
if (!soc) exit(1, 'Can\'t open socket on port '+port+'.');

ldap_init(socket:soc);

# Bind to the LDAP server, using credentials if they are supplied
if (!empty_or_null(ldap_user) && !empty_or_null(ldap_pass))
{
  bind = ldap_bind_request(name:ldap_user, pass:ldap_pass);
  ret = ldap_request_sendrecv(data:bind);
  if (isnull(ret) || ret[0] != LDAP_BIND_RESPONSE) exit(1, 'Failed to bind to the LDAP server listening on port '+port+'.');

  # Make sure authentication was successful
  ret = ldap_parse_bind_response(data:ret[1]);
  if (ret[0] == LDAP_INVALID_CREDENTIALS) exit(1, 'Failed to authenticate to the LDAP server listening on port '+port+' using the supplied credentials.');
}

# Initiate the LDAP search
search = ldap_search_request(object:obj, filter:'objectClass', attributes:make_list('*'), scope:0x00);
ret = ldap_request_sendrecv(data:search);

users = make_array();
members = make_list();
totalmembers = 0;
repeat {
  if (isnull(ret) || ret[0] != LDAP_SEARCH_RES_ENTRY)
    break;

  data = ldap_parse_search_entry(data:ret[1]);
  for (i=0; i<max_index(data); i++)
  {
    attrlist = data[i];
    if (attrlist[0] == 'member')
    {
      vals = attrlist[1];
      for (j=0; j < max_index(vals); j++)
      {
        totalmembers++;
        users[vals[j]] = 1;
        if (totalmembers == max_results) break;
      }
    }
  }
  ret = ldap_recv_next();
} until (isnull(ret) || totalmembers >= max_results);

# iteratively search
obj = domain_obj;
search_filters = make_nested_list(
  make_array(
    "object", obj,
    "filter", "group",
    "scope", 0x02
  ),
  make_array(
    "object", obj,
    "filter", "posixGroup",
    "scope", 0x02
  )
);

groups = make_array();
foreach search_val (search_filters)
{
  filters = make_list();
  filter = make_array();
  filter['left'] = 'objectclass';
  filter['conditional'] = LDAP_FILTER_EQUAL;
  filter['right'] = search_val["filter"];
  filters[0] = filter;
  search = ldap_search_request(object:search_val["object"], filter:filters, scope:search_val["scope"]);
  ret = ldap_request_sendrecv(data:search);

  repeat {
    if (isnull(ret) || ret[0] != LDAP_SEARCH_RES_ENTRY)
      break;
    data = ldap_parse_search_object_name(data:ret[1]);
    if ('domain admins' >< tolower(data))
      groups[data - strcat(",", obj)] = 1;
    ret = ldap_recv_next();
  } until (isnull(ret));
}

# if we found the domain admins group, search it for members
if (len(groups) > 0)
{
  foreach group (keys(groups))
  {
    obj = group + ',' + domain_obj;
    # reusing var
    search_filters = make_nested_list(
      make_array(
	"object", "cn=users," + obj,
	"filter", "person",
	"scope", 0x01
      ),
      make_array(
	"object", obj,
	"filter", "posixAccount",
	"scope", 0x02
      ),
      make_array(
	"object", obj,
	"filter", "person",
	"scope", 0x02
      )
    );

    foreach search_val (search_filters)
    {
      filter = make_array();
      filter['left'] = 'objectClass';
      filter['conditional'] = LDAP_FILTER_EQUAL;
      filter['right'] = search_val["filter"];

      filters = make_list();
      filters[0] = filter;

      search = ldap_search_request(object:search_val["object"], filter:filters, scope:search_val["scope"]);
      ret = ldap_request_sendrecv(data:search);

      repeat {
	if (isnull(ret) || ret[0] != LDAP_SEARCH_RES_ENTRY)
	  break;
	data = ldap_parse_search_object_name(data:ret[1]);
	user_str = string (data - strcat(",", obj));
	users[user_str] = 1;
	ret = ldap_recv_next();
      } until ( isnull(ret));
    }
  }
}

count = 0;
foreach user (keys(users))
{
  count++;
  set_kb_item(name:"LDAP/DomainAdmins/Members/"+count, value:user);
  if (totalmembers == max_results) break;
  totalmembers++;
  members = make_list(members, user);
}

if (max_index(members) > 0)
{
  count = len(members);
  verbose_report = '';
  for (i = 1; i <= count; i++)
  {
    set_kb_item(name:"LDAP/DomainAdmins/Members/"+i, value:members[i-1]);
    verbose_report += '  | ' + members[i-1] + '\n';
  }
  if (report_verbosity > 0)
  {
    report = 'Nessus enumerated the following members of the '+group+' group :\n';
    report += verbose_report;
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
exit(0, 'Nessus wasn\'t able to enumerate the members of the '+group+' group in the LDAP server listening on port '+port+'.');
