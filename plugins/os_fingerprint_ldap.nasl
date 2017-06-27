#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58076);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/04/04 01:52:39 $");

  script_name(english:"OS Identification : LDAP");
  script_summary(english:"Identifies devices based on its LDAP banner");

  script_set_attribute(
    attribute:"synopsis",
    value:
"It is possible to identify the remote operating system based on an
LDAP query."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote operating system can be identified through its response
to a search request with a filter set to 'objectClass=*'."
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/21");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("ldap_search.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"ldap", exit_on_fail:TRUE);

vv = get_kb_item("LDAP/"+port+"/vendorVersion");
vn = get_kb_item("LDAP/"+port+"/vendorName");
ncs = get_kb_list("LDAP/"+port+"/namingContexts");


fingerprint = "";
if (vv) fingerprint = strcat(fingerprint, "; vendorVersion=", vv);
if (vn) fingerprint = strcat(fingerprint, "; vendorName=", vn);
if (ncs && max_index(ncs) > 0) fingerprint = strcat(fingerprint, "; namingContexts=", join(sep:" & ", ncs));
if (!fingerprint) exit(0, "The LDAP server listening on port "+port+" does not provide information that can be used for fingerprinting.");
fingerprint = substr(fingerprint, 2);


kb_base = "Host/OS/LDAP";              # nb: should *not* end with a slash
set_kb_item(name:kb_base+"/Fingerprint", value:fingerprint);

default_confidence = 90;
default_type = 'general-purpose';


# Variables for each OS:
#
# nb: for the arrays, *all* elements must be found for a match to occur.
# name            description of the device
# confidence      confidence level
# dev_type        type of the device (eg, embedded, printer, etc).
# vendorNames     regex to be matched against vendorName.
# vendorVersions  regex to be matched against vendorVersion.
# namingContexts  array of regexes to match against namingContexts.

i = 0;
name           = make_array();
confidence     = make_array();
dev_type       = make_array();
vendorNames    = make_array();
vendorVersions = make_array();
namingContexts = make_array();

name[i]           = "IBM OS/400";
vendorNames[i]    = "(International Business Machines|IBM)";
namingContexts[i] = "^OS400-SYS=";
i++;


n = i;
for (i=0; i<n; i++)
{
  if (strlen(vn) == 0)
  {
    if (strlen(vendorNames[i]) > 0) continue;
  }
  else
  {
    if (
      strlen(vendorNames[i]) > 0 &&
      !eregmatch(pattern:vendorNames[i], string:vn)
    ) continue;
  }

  if (strlen(vv) == 0)
  {
    if (strlen(vendorVersions[i]) > 0) continue;
  }
  else
  {
    if (
      strlen(vendorVersions[i]) > 0 &&
      !eregmatch(pattern:vendorVersions[i], string:vv)
    ) continue;
  }

  if (isnull(ncs) || max_index(ncs) == 0)
  {
    if (strlen(namingContexts[i]) > 0) continue;
  }
  else
  {
    if (
      strlen(namingContexts[i]) > 0 &&
      !egrep(pattern:namingContexts[i], string:join(sep:'\n', ncs))
    ) continue;
  }

  # If we get here, we found it.
  name = name[i];

  if (confidence[i]) conf = confidence[i];
  else conf = default_confidence;

  if (dev_type[i]) type = dev_type[i];
  else type = default_type;

  set_kb_item(name:kb_base, value:name);
  set_kb_item(name:kb_base+"/Confidence", value:conf);
  set_kb_item(name:kb_base+"/Type", value:type);

  exit(0);
}
exit(0, "Nessus was not able to identify the OS from its LDAP service on port "+port+".");
