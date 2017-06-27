#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55814);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/09/24 20:59:27 $");

  script_name(english:"Adobe Media Server Unsupported Version Detection");
  script_summary(english:"Checks version gathered by remote check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Adobe Media Server installed that
is no longer supported.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Adobe Media Server
(formerly Adobe Flash Media Server) on the remote host is no longer
supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://www.adobe.com/support/products/enterprise/eol/eol_matrix.html#amss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d8438d8c");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/programs/policies/supported.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/adobe-media-server-standard.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Adobe Media Server that is currently
supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/11");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_media_server");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:adobe:media_server");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("adobe_fms_detect.nasl");
  script_require_ports("Services/rtmp");
  script_require_keys("rtmp/adobe_fms");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port    = get_kb_item_or_exit("Services/rtmp");
version = get_kb_item_or_exit("rtmp/" + port + "/adobe_fms/version");
source  = get_kb_item_or_exit("rtmp/" + port + "/adobe_fms/version_source");

ver = split(version, sep:'.', keep:FALSE);
for (i=0;i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] < 5)
{
  register_unsupported_product(product_name:"Adobe Media Server", version:version, cpe_base:"adobe:flash_media_server");

  if (report_verbosity > 0)
  {
    report =
      '\n  Version source       : ' + source +
      '\n  Installed version    : ' + version +
      '\n  Supported version(s) : 5.0' +
      '\n  URL                  : http://www.nessus.org/u?d8438d8c' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Adobe Media Server", port, version);
