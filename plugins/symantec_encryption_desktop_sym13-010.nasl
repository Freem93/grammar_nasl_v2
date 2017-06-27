#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69307);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id("CVE-2013-1610");
  script_bugtraq_id(61489);
  script_osvdb_id(95924);

  script_name(english:"Symantec Encryption Desktop Unquoted Search Path");
  script_summary(english:"Checks for unquoted service");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an encryption application installed that
uses an unquoted service path.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Encryption Desktop or Symantec PGP Desktop
installed on the remote host has a service that uses an unquoted search
path that contains at least one whitespace.  A local attacker could gain
elevated privileges by inserting an executable file in the path of the
affected service.");
  script_set_attribute(attribute:"solution", value:"Upgrade to Symantec Encryption Desktop 10.3.0 MP3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20130801_01
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39270a1e");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:encryption_desktop");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:pgp_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services_params.nasl");
  script_require_keys("SMB/Services/Enumerated");

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");
include("smb_header.inc");

function extract_service_path()
{
  local_var item, idx;

  item = _FCT_ANON_ARGS[0];
  # If the first character is a '"', the path is enclosed, so just use
  # that to extract the path
  if (item =~ '^"')
  {
    item = ereg_replace(pattern:'^("[^"]+").*', string:item, replace:"\1");
  }
  else
  {
    # First extract any extra paths from the arguments
    item = ereg_replace(pattern:'^(\\s+)?("?[A-Za-z]:\\\\[^:]+).*', string:item, replace:"\2");

    # Service arguments use '-' or '/' characters for flags
    # First look for '/' flags
    if ('/' >< item)
    {
      idx = stridx(item, '/');
      item = item - substr(item, idx);
    }

    # Now look for ' -' flags
    if (' -' >< item)
    {
      idx = stridx(item, ' -');
      item = item - substr(item, idx);
    }

    # Some arguments don't use a flag
    item = ereg_replace(pattern:'^([A-Za-z]:\\\\.*\\\\[^\\.]+\\.[^\\s]+).*', string:item, replace:"\1");
  }
  return item;
}

service = get_kb_item_or_exit('SMB/svc/PGP RDD Service/path');
path = extract_service_path(service);

# If there is a space in the path and it isn't enclosed in '"'
# there is a problem
if (' ' >< path && path !~ '^".*"$')
{
  # Make sure the whitespace isn't only at the end of the path
  if (path !~ '^[^\\s]+\\s+$')
  {
    # Set a KB item so we can ignore this in the generic check if this
    # plugin catches it
    set_kb_item(name:"SMB/Unquoted/PGP RDD Service", value:"TRUE");
    if (report_verbosity > 0)
    {
      report =
        '\nNessus found the following service with an untrusted path : ' +
        '\n  Service name : PGP RDD Service ' +
        '\n  Service path : ' + path + '\n';
      security_warning(port:get_kb_item('SMB/transport'), extra:report);
    }
    else security_warning(get_kb_item('SMB/transport'));
    exit(0);
  }
}
audit(AUDIT_HOST_NOT, 'affected');
