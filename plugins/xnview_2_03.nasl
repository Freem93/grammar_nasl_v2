#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66859);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/06/19 10:47:27 $");

  script_cve_id("CVE-2013-3246", "CVE-2013-3247");
  script_bugtraq_id(60233, 60235);
  script_osvdb_id(93746, 93747);

  script_name(english:"XnView 2.x < 2.03 Multiple Buffer Overflow Vulnerabilities");
  script_summary(english:"Checks XnView.exe's Product Version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains an application that is affected by
multiple buffer overflow vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of XnView installed on the remote Windows host is 2.x,
earlier than 2.03.  It is, therefore, reportedly affected by the
following buffer overflow vulnerabilities:

  - A stack-based buffer overflow exists in the 'XCF' image
    handling layer.  (CVE-2013-3246)

  - A heap-based buffer overflow exists when handling
    decompression of RLE layers in a specially crafted 'XCF'
    file.  (CVE-2013-3247)"
  );
  # Release notes
  script_set_attribute(attribute:"see_also", value:"http://newsgroup.xnview.com/viewtopic.php?f=35&t=28072");
  script_set_attribute(attribute:"solution", value:"Upgrade to XnView version 2.03 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:xnview:xnview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("xnview_rgbe_overflow.nasl");
  script_require_keys("SMB/XnView/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "SMB/XnView";
get_kb_item_or_exit(kb_base+"/Installed");
path = get_kb_item_or_exit(kb_base+"/Path");
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);

# Check the version number.
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# 2.00 < 2.03
if (ver[0] == 2 && ver[1] < 3)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.03\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "XnView", version, path);
