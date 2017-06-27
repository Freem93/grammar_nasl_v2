#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71864);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/01/09 02:50:13 $");

  script_cve_id("CVE-2013-3937", "CVE-2013-3939", "CVE-2013-3941");
  script_bugtraq_id(64438, 64439, 64441);
  script_osvdb_id(101144, 101145, 101146);

  script_name(english:"XnView 2.x < 2.13 Multiple Buffer Overflows");
  script_summary(english:"Checks XnView.exe's product version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains an application that is affected by
multiple buffer overflow vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of XnView 2.x installed on the remote Windows host is
earlier than 2.13.  It is, therefore, reportedly affected by the
following buffer overflow vulnerabilities:

  - A remote, heap-based buffer overflow vulnerability
    exists due to an error in the 'xnview.exe' file when
    processing BMP files. An attacker can exploit this issue
    through a specially crafted 'biBitCount' field.
    (CVE-2013-3937)

  - A remote, heap-based buffer overflow vulnerability
    exists because XnView fails to properly bounds-check
    user-supplied input before copying it to an
    insufficiently sized memory buffer. Specifically, this
    issue occurs due to a sign-extension error in the
    'xnview.exe' file when processing RLE strip lengths in
    RGB files. An attacker can exploit this issue through a
    specially crafted RLE strip size field. (CVE-2013-3939)

  - A remote, heap-based buffer overflow vulnerability
    exists because XnView fails to properly bounds-check
    user-supplied input before copying it to an
    insufficiently sized memory buffer. Specifically, this
    issue occurs in 'Xjp2.dll' when using the Csiz parameter
    of the SIZ marker and lqcd field of the QCD marker. An
    attacker can exploit this issue through a specially
    crafted JPEG2000 file. (CVE-2013-3941)"
  );
  # Release notes
  script_set_attribute(attribute:"see_also", value:"http://newsgroup.xnview.com/viewtopic.php?f=35&t=29087");
  script_set_attribute(attribute:"solution", value:"Upgrade to XnView version 2.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:xnview:xnview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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

# 2.00 < 2.13
if (ver[0] == 2 && ver[1] < 13)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.13\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "XnView", version, path);
