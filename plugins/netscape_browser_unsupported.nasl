#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31343);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/12/01 16:04:23 $");

  script_name(english:"Netscape Browser Unsupported Version Detection");
  script_summary(english:"Checks if Netscape is installed.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is no longer
supported.");
  script_set_attribute(attribute:"description", value:
"Netscape Navigator or Netscape Browser is installed on the remote
host. Official support for all Netscape client products, including its
browser, ended as of March 1st, 2008.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://web.archive.org/web/20081223031725/http://blog.netscape.com/2007/12/28/end-of-support-for-netscape-web-browsers/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3771e222");
  script_set_attribute(attribute:"solution", value:
"Switch to another browser, such as Mozilla Firefox, which the Netscape
Team recommends.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netscape:navigator");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("netscape_browser_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/Netscape/installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

if (get_kb_item("SMB/Netscape/installed"))
{
  register_unsupported_product(product_name:"Netscape Navigator",
                               cpe_base:"netscape:navigator");

  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  security_hole(port);
}
else exit(0, "The remote Windows host does not have Netscape Navigator.");
