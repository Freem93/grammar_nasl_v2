# @DEPRECATED@
#
# This script has been deprecated as Winamp has been taken over
# from AOL by Radionomy and support continues.
#
# Disabled on 2014/05/09.
#

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71572);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/09/24 23:21:22 $");

  script_name(english:"Winamp Unsupported");
  script_summary(english:"Checks for Winamp");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a multimedia application that is no
longer supported.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Winamp, a media player for Windows. As of
December 20, 2013, the vendor no longer provides security fixes for
the installed product.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # EOL announcement
  script_set_attribute(attribute:"see_also", value:"http://blogs.wsj.com/corporate-intelligence/2013/11/20/rip-winamp/");
  # http://arstechnica.com/business/2013/11/after-15-years-of-llama-whipping-aol-shuts-down-winamp-for-good/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc21981b");
  script_set_attribute(attribute:"solution", value:"Remove Winamp and install a supported multimedia application.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:winamp");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

# Deprecated.
exit(0, "Support for Winamp continues.");


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

path = get_kb_item_or_exit("SMB/Winamp/Path");
ver = get_kb_item_or_exit("SMB/Winamp/Version");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (defined_func("report_xml_tag")) report_xml_tag(tag:"UnsupportedProduct:nullsoft:winamp:"+ver, value:"true");

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver  +
    '\n  Solution          : Remove Winamp' +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
