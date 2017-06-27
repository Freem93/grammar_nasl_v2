#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62121);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/09/18 14:42:19 $");

  script_bugtraq_id(55482);
  script_osvdb_id(85359);

  script_name(english:"XnView < 1.99.1 JPEG Compressed TIFF Image Multiple Header Value Handling Overflow");
  script_summary(english:"Checks XnView.exe's Product Version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains an application with a buffer overflow
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of XnView installed on the remote Windows host is earlier
than 1.99.1.  It is, therefore, reportedly affected by a heap-based
buffer overflow vulnerability.  This is due to an error in the handling
of TIFF image files having JPEG compression.  Specially crafted files of
this type can contain certain 'ImageLength' and 'ImageWidth' header
values which trigger the vulnerability.  Arbitrary code execution is
possible."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.fuzzmyapp.com/advisories/FMA-2011-016/FMA-2011-016-EN.xml");
  # Release notes
  script_set_attribute(attribute:"see_also", value:"http://newsgroup.xnview.com/viewtopic.php?f=35&t=26736");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to XnView version 1.99.1 or later as that reportedly resolves
the issue."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:xnview:xnview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

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

# 1.98.x and 1.99.x <= 1.99.1 are affected
if (
  ver[0] == 1 &&
  (
    ver[1] == 98 ||
    (ver[1] == 99 && ver[2] < 1)
  )
)
{
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    if (isnull(path)) path = "n/a";

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.99.1\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "XnView", version, path);
