#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99907);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/01 19:18:42 $");

  script_name(english:"IBM MQ Unsupported Version Detection (credentialed check)");
  script_summary(english:"Checks the version of IBM MQ.");

  script_set_attribute(attribute:"synopsis", value:
"A message queuing application installed on the remote host is no
longer supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
IBM MQ (formerly IBM WebSphere MQ) on the remote Windows host is no
longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www-03.ibm.com/software/products/en/websphere-mq");
  script_set_attribute(attribute:"see_also", value:"http://www-03.ibm.com/software/products/en/ibm-mq");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/software/support/lifecycle/index_w.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of IBM MQ that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ", "SMB/Registry/Enumerated");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("install_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

appname = 'IBM WebSphere MQ';
eol_date = '';
eol_url  = '';

eol_data = make_nested_array(
  "^[0-6]($|[^0-9])", make_array(
                        'eol_date', '2015/09/30',
                        'eol_url', 'n/a'),

  "^7\.0($|[^0-9])", make_array(
                        'eol_date', '2015/09/30',
                        'eol_url', 'http://www.ibm.com/common/ssi/fcgi-bin/ssialias?subtype=ca&infotype=an&appname=iSource&supplier=897&letternum=ENUS914-067'),

  "^7\.0\.1($|[^0-9])", make_array(
                        'eol_date', '2015/09/30',
                        'eol_url', 'http://www.ibm.com/common/ssi/fcgi-bin/ssialias?subtype=ca&infotype=an&appname=iSource&supplier=897&letternum=ENUS914-067'),

  "^7\.1($|[^0-9])", make_array(
                        'eol_date', '2017/04/30',
                        'eol_url', 'http://www.ibm.com/common/ssi/fcgi-bin/ssialias?subtype=ca&infotype=an&appname=iSource&supplier=897&letternum=ENUS916-072')

#  Uncomment on or after 2018/04/30
#  "^7\.5($|[^0-9])", make_array(
#                        'eol_date', '2018/04/30',
#                        'eol_url', 'http://www.ibm.com/common/ssi/fcgi-bin/ssialias?subtype=ca&infotype=an&appname=iSource&supplier=897&letternum=ENUS916-117')
);

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
path = install['path'];
version = install['version'];

if (!empty_or_null(install['port']))
  exit(0, appname + ' installation listening on port ' + install['port'] + ' was detected remotely and will not be checked by this plugin.');

ver = pregmatch(string:version, pattern:"^([0-9.]+)");
if(empty_or_null(ver)) audit(AUDIT_UNKNOWN_APP_VER, appname);
else ver = ver[1];

currently_supported = "7.5.0 and later";
currently_unsupported_cutoff = "7.5.0";

if (ver_compare(ver:ver, fix:currently_unsupported_cutoff, strict:FALSE) < 0)
{
  register_unsupported_product(product_name:"IBM WebSphere MQ",
                               cpe_base:"ibm:websphere_mq", version:version);

  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  foreach regex (keys(eol_data))
  {
    if (ver =~ regex)
    {
      eol_date = eol_data[regex]['eol_date'];
      eol_url  = eol_data[regex]['eol_url'];
    }
  }

  report =
    '\n  Path               : ' + path +
    '\n  Installed version  : ' + version +
    '\n  Supported versions : ' + currently_supported +
    '\n  EOL Date           : ' + eol_date +
    '\n  EOL URL            : ' + eol_url +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver, path);
