#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73598);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 21:08:39 $");

  script_name(english:"Unsupported Brocade Fabric OS");
  script_summary(english:"Checks if a version of Fabric OS is unsupported.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an obsolete operating system.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Fabric OS on the remote
host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.brocade.com/en/support/product-end-of-life.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Fabric OS that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:brocade:fabric_os");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl");
  script_require_keys("Host/OS");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("snmp_func.inc");
include("misc_func.inc");

ver = NULL;

os = get_kb_item_or_exit('Host/OS');

match = eregmatch(string:os, pattern:'Fabric OS ([0-9a-zA-Z._-]+)$');
if (match)
{
  ver = match[1];
}

# SNMP
else if ("Brocade Switch" >< os)
{
  community = get_kb_item("SNMP/community");
  if (community)
  {
    port = get_kb_item("SNMP/port");
    if (!port) port = 161;
    if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

    soc = open_sock_udp(port);
    if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");

    # Get version
    txt = snmp_request(socket:soc, community:community, oid:"1.3.6.1.4.1.1588.2.1.1.1.1.6.0");
    if (txt) ver = txt;
    else audit(AUDIT_UNKNOWN_APP_VER, "Fabric OS");
  }
}

if (isnull(ver)) audit(AUDIT_OS_NOT, "Fabric OS");

latest = '7.4.0';
eoa_date = NULL;
eoa_url = NULL;

# 7.1.x
if (
  ver =~ "^7\.1(\.|$)"
)
{
  eoa_date = "2015-04-15";
  # http://www.brocade.com/content/brocade/en/backend-content/pdf-page.html?/content/dam/common/documents/content-types/end-of-life-notice/brocade-fos-7.1.x-eoa-notice.pdf
  eoa_url = "http://www.nessus.org/u?ca91d510";
}

# 5.1.x - 5.3.x
else if (
  ver =~ "^5\.[1-3](\.|$)"
)
{
  eoa_date = "2009-02-04";
  # http://community.brocade.com/dtscp75322/attachments/dtscp75322/fibre/1316/2/FOS+5.3.x+EOA+Notice+v2.0.pdf
  eoa_url  = "http://www.nessus.org/u?e6145511";
}

# 2.6.2 and earlier
else if (ver =~ "^2\.[0-6]([^0-9]|$)")
{
  eoa_date = "2008-06-19";
  # https://web.archive.org/web/20150505044358/http://www.brocade.com/downloads/documents/end_of_availability_notice/FOS%202%206%202%20EOL%20v1.0.pdf
  eoa_url  = "http://www.nessus.org/u?137106c3";
}

# 3.x / 5.0.x
else if (
  ver =~ "^3\." ||
  ver =~ "^5\.0(\.|$)"
)
{
  eoa_date = "2008-05-01";
  # https://web.archive.org/web/20081125080318/http://www.brocade.com/downloads/documents/end_of_availability_notice/FOS%203%20x%205%200%20x%20and%20SFOS%20EOL%20v0%204%20_103007_.pdf
  eoa_url  = "http://www.nessus.org/u?2a46cb3b";
}

# 4.2.x - 4.4.x
else if (
  ver =~ "^4\.[2-4]([^0-9]|$)"
)
{
  eoa_date = "2007-03-31";
  # https://web.archive.org/web/20150505021442/http://www.brocade.com/downloads/documents/end_of_availability_notice/3_1_X4_4_X_7_3_XEOL052306.pdf
  eoa_url  = "http://www.nessus.org/u?3fc9f0cb";
}

# 4.1.x - 4.2.0x
else if (
  ver =~ "^4\.1([^0-9]|$)" ||
  ver =~ "^4\.2\.0([^0-9]|$)"
)
{
  eoa_date = "2005-12-31";
  # https://web.archive.org/web/20081203053619/http://www.brocade.com/downloads/documents/end_of_availability_notice/2_6_13_1_24_2_0EOLExtension.pdf
  eoa_url  = "http://www.nessus.org/u?8f7d93bb";
}

# 4.0.1x - 4.0.2x
else if (
  ver =~ "^4\.0\.[12]([^0-9]|$)"
)
{
  eoa_date = "2004-08-31";
  # https://web.archive.org/web/20150505030101/http://www.brocade.com/downloads/documents/end_of_availability_notice/2_6_03_0_24_0_2EOLrev3.pdf
  eoa_url  = "http://www.nessus.org/u?0a22d9c2";
}

# 4.0.0x
else if (ver =~ "^4\.0\.0([^0-9]|$)")
{
  eoa_date = "2004-02-29";
  # https://web.archive.org/web/20150505045910/http://www.brocade.com/downloads/documents/end_of_availability_notice/3_0_04_0_0EOL082103.pdf
  eoa_url  = "http://www.nessus.org/u?abb3b15d";
}

if (isnull(eoa_date)) exit(0, 'Fabric OS ' + ver + ' is still supported.');

register_unsupported_product(
  product_name:'Brocade Fabric OS',
  cpe_class:CPE_CLASS_OS,
  version:ver,
  cpe_base:"brocade:fabric_os"
);

if (report_verbosity > 0)
{
  report =
    '\n  Installed Fabric OS version : ' + ver +
    '\n  EOA date                    : ' + eoa_date +
    '\n  EOA URL                     : ' + eoa_url  +
    '\n  Latest Fabric OS version    : ' + latest + '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
