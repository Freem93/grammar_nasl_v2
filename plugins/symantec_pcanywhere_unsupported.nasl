#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57859);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/12/07 20:08:15 $");

  script_name(english:"Symantec pcAnywhere Unsupported");
  script_summary(english:"Checks the version of pcAnywhere.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an unsupported version of a remote access
application installed.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Symantec pcAnywhere on
the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/en_US/article.HOWTO98455.html");
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/connect/blogs/pcanywhere-eol");
  script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/en_US/defaultProductLanding.52418.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to a version of pcAnywhere that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:pcanywhere");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("symantec_pcanywhere_installed.nasl");
  script_require_keys("SMB/Symantec pcAnywhere/Path", "SMB/Symantec pcAnywhere/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

path = get_kb_item_or_exit('SMB/Symantec pcAnywhere/Path');
version = get_kb_item_or_exit('SMB/Symantec pcAnywhere/Version');

register_unsupported_product(product_name:"Symantec pcAnywhere",
                               cpe_base:"symantec:pcanywhere", version:version);

port = get_kb_item('SMB/transport');
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n  Path                 : ' + path +
    '\n  Installed version    : ' + version +
    '\n  EOL URL              : https://support.symantec.com/en_US/article.HOWTO98455.html\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
exit(0);
