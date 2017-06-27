#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(57347);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/02 14:37:09 $");

  script_cve_id("CVE-2011-4141");
  script_bugtraq_id(51073);
  script_osvdb_id(77741);
  script_xref(name:"IAVA", value:"2011-A-0175");

  script_name(english:"RSA SecurID Software Token < 4.1.1 Insecure Library Loading");
  script_summary(english:"Checks version of SecurID.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of RSA SecurID Software
Token 3.0, 4.0, or 4.1 earlier than 4.1.1.  As such, it is reportedly
affected by an insecure library loading vulnerability.  If an attacker
can trick a user on the affected system into opening a specially
crafted Software Token file, this issue could be leveraged to execute
arbitrary code subject to the user's privileges.");

  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/520878/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Dec/88");
  script_set_attribute(attribute:"solution", value:
"Upgrade to RSA SecurID Software Token 4.1.1 (4.1.1.836) or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/20");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("rsa_securid_software_token_installed.nasl");
  script_require_keys("SMB/RSA SecurID Software Token/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('SMB/RSA SecurID Software Token/Version');
path = get_kb_item_or_exit('SMB/RSA SecurID Software Token/Path');

fix = '4.1.1.836';
if (
  ver =~ '^3\\.' || 
  ver =~ '^4\\.0\\.' ||
  (ver =~ '^4\\.1\\.' && ver_compare(ver:ver, fix:fix) == -1)
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : 4.1.1.836\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
  exit(0);
}
else exit(0, 'The RSA SecurID Software Token '+ver+' install on the host is not affected.');
