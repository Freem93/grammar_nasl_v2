#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71884);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/10 20:49:25 $");

  script_cve_id("CVE-2013-6886");
  script_bugtraq_id(64560);
  script_osvdb_id(101481, 101482, 101483);

  script_name(english:"RealVNC < 5.0.7 Multiple Local Privilege Escalations");
  script_summary(english:"Checks version of RealVNC");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a remote control application that is affected by
multiple local privilege escalation vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of RealVNC on the remote host is earlier than 5.0.7.  As
such, it is affected by multiple privilege escalation
vulnerabilities :

  - A local privilege escalation vulnerability exists that
    is triggered by a specially crafted argument to the
    vncserver-x11 binary on UNIX / Linux. (CVE-2013-6886)

  - A local privilege escalation vulnerability exists that
    is triggered by a specially crafted argument to the Xvnc
    binary on UNIX / Linux. (CVE-2013-6886)

  - A local privilege escalation vulnerability exists that
    is triggered by a specially crafted argument to the
    vncserver binary on Mac OS X. (CVE-2013-6886)");
  script_set_attribute(attribute:"see_also", value:"http://www.realvnc.com/products/vnc/documentation/5.0/release-notes/");
  script_set_attribute(attribute:"solution", value:"Upgrade to RealVNC 5.0.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:realvnc:realvnc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("realvnc_java_viewer_detect.nbin", "os_fingerprint.nasl");
  script_require_keys("Host/RealVNC_Java_Viewer");
  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");

appname = "RealVNC";
kb_base = "Host/RealVNC_Java_Viewer";
port = get_kb_item_or_exit(kb_base + "/Port");
version = get_kb_item_or_exit(kb_base + "/Version");
release = get_kb_item_or_exit(kb_base + "/Release");

if (report_paranoia < 2)
{
  os = get_kb_item_or_exit("Host/OS");
  if (!isnull(os) && ("Windows" >< os)) audit(AUDIT_OS_NOT, "Unix or Mac OS X", os);
}

fix = "5.0.7";
if (version =~ "^5\.0\.6($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version + " (" + release + ")" +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, version);
