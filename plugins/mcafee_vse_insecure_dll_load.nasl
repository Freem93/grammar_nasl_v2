#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50986);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_cve_id("CVE-2009-5118");
  script_bugtraq_id(45080);
  script_osvdb_id(69503);
  script_xref(name:"Secunia", value:"41482");

  script_name(english:"McAfee VirusScan Enterprise Path Subversion Arbitrary DLL Injection Code Execution");
  script_summary(english:"Checks version of VSE");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a program that allows arbitrary code
execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of McAfee VirusScan Enterprise installed on the remote
Windows host is earlier than 8.7i.  Such versions insecurely look in
their current working directory when resolving DLL dependencies, such
as for 'traceapp.dll'.

Attackers may exploit the issue by placing a specially crafted DLL
file and another file associated with the application in a location
controlled by the attacker.  When the associated file is launched, the
attacker's arbitrary code can be executed."
  );
  # https://web.archive.org/web/20120731045334/https://kc.mcafee.com/corporate/index?page=content&id=SB10013
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae04902e");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to VirusScan Enterprise 8.7i or later, or apply the hotfix
when it is released."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan_enterprise");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_installed.nasl");
  script_require_keys("Antivirus/McAfee/product_name", "Antivirus/McAfee/product_version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


prod = get_kb_item_or_exit("Antivirus/McAfee/product_name");
ver = get_kb_item_or_exit("Antivirus/McAfee/product_version");

if (prod != 'McAfee VirusScan Enterprise') exit(0, prod + ' is not affected.');

# nb: we want to flag versions 8.5 and earlier, at least
#     until McAfee releases an update for 8.5 itself.
if (ver_compare(ver:ver, fix:'8.6', strict:FALSE) < 0)
{
  port = get_kb_item('SMB/transport');

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : 8.7i\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, prod + ' ' + ver + ' is not affected.');
