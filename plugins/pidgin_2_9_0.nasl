#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55436);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2011-2485");
  script_bugtraq_id(48425);
  script_osvdb_id(73333);
  script_xref(name:"Secunia", value:"45037");

  script_name(english:"Pidgin < 2.9.0 gdk_pixbuf__gif_image_load() Denial of Service");
  script_summary(english:"Does a version check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An instant messaging client installed on the remote Windows host is
affected by a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Pidgin installed on the remote host is earlier than
2.9.0.  As such, it is potentially affected by a denial of service
vulnerability. 

The function 'gdk_pixbuf__gif_image_load' contains an error that
allows a crafted GIF image file, when used as a buddy image, to cause
memory exhaustion and finally process termination.");
  script_set_attribute(
    attribute:"see_also",
    value:"http://pidgin.im/news/security/?id=52"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://developer.pidgin.im/wiki/ChangeLog"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Pidgin 2.9.0 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2011/06/24");
  script_set_attribute(attribute:"patch_publication_date",value:"2011/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pidgin:pidgin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("pidgin_installed.nasl");
  script_require_keys("SMB/Pidgin/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Pidgin/Version");
fixed_version = '2.9.0';

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  path = get_kb_item_or_exit("SMB/Pidgin/Path");
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    report =
      '\n  Path               : ' + path +
      '\n  Installed version  : ' + version +
      '\n  Fixed version      : ' + fixed_version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "Pidgin " + version + " is installed and hence not affected.");
