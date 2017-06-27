#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24345);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/01/14 03:46:11 $");

  script_cve_id("CVE-2007-0651", "CVE-2007-0652");
  script_bugtraq_id(22554);
  script_osvdb_id(33188, 33189, 33190, 33191);

  script_name(english:"MailEnable Web Mail Client Multiple Vulnerabilities (XSS, CSRF)");
  script_summary(english:"Checks version of MailEnable");

  script_set_attribute(attribute:"synopsis", value:
"The remote webmail service is affected by multiple issues." );
  script_set_attribute(attribute:"description", value:
"The Web Mail Client bundled with the version of MailEnable installed
on the remote host reportedly fails to properly sanitize email
messages and various script parameters of malicious script code, which
can lead to cross-site scripting, cross-site request forgery, and
script insertion attacks against the affected software." );
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2007-38/advisory/" );
  script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/Professional20-ReleaseNotes.txt" );
  script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/Enterprise20-ReleaseNotes.txt" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to MailEnable Professional Edition 1.85 / 2.37 or Enterprise
1.42 / 2.37 or later as they are rumoured to address the issues." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/15");
  script_set_attribute(attribute:"vuln_publication_date", value: "2007/02/14");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mailenable:mailenable");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("mailenable_detect.nasl");
  script_require_keys("SMB/MailEnable/Installed");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("SMB/MailEnable/Installed")) exit(0);
if (get_kb_item("SMB/MailEnable/Standard")) prod = "Standard";
if (get_kb_item("SMB/MailEnable/Professional")) prod = "Professional";
else if (get_kb_item("SMB/MailEnable/Enterprise")) prod = "Enterprise";


# Check version of MailEnable.
if (prod == "Professional" || prod == "Enterprise")
{
  kb_base = "SMB/MailEnable/" + prod;
  ver = get_kb_item(kb_base+"/Version");
  if (isnull(ver)) exit(0);

  if (
    # 1.0-1.84 Professional Edition
    # 2.0-2.36 Professional Edition
    (prod == "Professional" && ver =~ "^(1\.([0-7]($|[0-9.])|8$|8[0-4])|2\.([0-2]($|[0-9.])|3($|[0-6])))") ||
    # 1.0-1.41 Enterprise Edition
    # 2.0-2.36 Enterprise Edition
    (prod == "Enterprise" && ver =~ "^(1\.([0-3]($|[0-9].)|4$|4[01])|2\.([0-2]($|[0-9.])|3($|[0-6])))")
  ) {
     security_warning(get_kb_item("SMB/transport"));
     set_kb_item(name: 'www/0/XSS', value: TRUE);
    }
}
