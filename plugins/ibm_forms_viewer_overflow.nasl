#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72026);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/06/02 22:14:36 $");

  script_cve_id("CVE-2013-5447");
  script_osvdb_id(100732);
  script_xref(name:"EDB-ID", value:"30789");
  script_xref(name:"IAVB", value:"2014-B-0004");

  script_name(english:"IBM Forms Viewer Stack Buffer Overflow");
  script_summary(english:"Checks version of IBM Forms Viewer");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
stack-based buffer overflow.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Forms Viewer on the remote host is affected by a
stack-based buffer overflow in the XDL form fontname tag parser.
This can allow an attacker to execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21657500");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-274/");
  script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/87911");
  script_set_attribute(attribute:"solution", value:"Upgrade to IBM Forms Viewer 4.0.0.3 or 8.0.1.1 or newer.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'IBM Forms Viewer Unicode Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:forms_viewer");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("ibm_forms_viewer_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "SMB/ibm_forms_viewer/Installed");
  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");

appname = "IBM Forms Viewer";
kb_base = "SMB/ibm_forms_viewer/";

port = get_kb_item("SMB/transport");
if (!port) port = 445;

fix4 = "4.0.0.3";
fix8 = "8.0.1.1";

report = "";
installs = get_kb_item_or_exit(kb_base + "installs");
for (i = 0; i < installs; i++)
{
  path = get_kb_item_or_exit(kb_base + "install/" + i + "/Path");
  ver = get_kb_item_or_exit(kb_base + "install/" + i + "/Version");

  if (ver =~ "^4\.0\." && (ver_compare(ver:ver, fix:fix4, strict:FALSE) == -1))
  {
    if (report_verbosity > 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + ver +
        '\n  Fixed version     : ' + fix4 +
        '\n';
    }
  }
  else if (ver =~ "^8\.0\." && (ver_compare(ver:ver, fix:fix8, strict:FALSE) == -1))
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix8 +
      '\n';
  }
}

if (report != "")
{
  if (report_verbosity > 0) security_warning(port:port, extra:report);
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname);

