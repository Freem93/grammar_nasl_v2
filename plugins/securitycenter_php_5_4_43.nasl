#TRUSTED 3c09cdf4515e9fb3f1611f22a132578ecd1c7933e092eafb94876bb7759532798f5a4d312c898a1677f98490816865d6d4f26a5760a29d099143230ccd6980b3b89b49bd9726a9ad99313cf571da13e3d6514272934d5c3107c200020991964d2ba656694e9a72cd43e498d874de2112fa569e4ef14655f46fedf2e45aafb3f6be3f81584cdf40484ac69360fbb2a93a8197b07f38be88e4d504a3242426eebb584a6adb495ce12b3b83f31b5bad250560c20055ad531c22cfd8102cf0bcec77c60aeed514213d1259bec75dc9fc422512f2efe6a14a64353ccb3e0f893b908ff501f94e577dc7b156380858d2068b933bb47f0942d81c2f605d186f16ab0767fa54549821eca0252c66f695a9a95d5cb80fdb5e31339e6d2ffca6473dc4c132fb41ce54aa92ae4b94c50188877ad38e41d760ac15ca2ebb5241638f4ba49fba76d5915fe3ef759a32b8667a1be414ab297cc7567d31300495712dc337a1a60e0dbb32b31fb63258a2de2c06fb6c97fafe16bbfa84f39af0859c04fcc330ff2189bb3ad0c795910115ef14a12b6a0998dbc33cab7672388f23f32879245fef046f43df5c66166d0802777e373df4d0b31748cff3dd34382035b1406a13e83750bd7f153e578dbb38671ff97736ca24e1ed11be839f931621dd71afaa5dca09733bb7c9b2cb7c1a63680a98c9bc0ae2781c5300cd418a998dff0153bde2acaa7a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89027);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/03");

  script_osvdb_id(124412);

  script_name(english:"Tenable SecurityCenter PHP Character Handling (TNS-2015-09)");
  script_summary(english:"Checks the version of PHP in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application is affected by a character handling
vulnerability in the bundled version of PHP.");
  script_set_attribute(attribute:"description", value:
"The SecurityCenter application installed on the remote host contains a
bundled version of PHP that is prior to 5.4.43. It is, therefore,
affected by an exclamation mark character handling issue in the
escapeshellcmd() and escapeshellarg() PHP functions. A remote attacker
can exploit this to substitute environment variables.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2015-09");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=69768");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.4.43");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.5.27");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.6.11");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_keys("Host/SecurityCenter/Version", "Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
sc_ver = get_kb_item_or_exit("Host/SecurityCenter/Version");
# Affected: SecurityCenter 4.8, 4.8.1, 5.0.0.1
if (sc_ver !~ "^(4\.8($|\.)|5\.0\.0\.)") audit(AUDIT_INST_VER_NOT_VULN, "SecurityCenter", sc_ver);

# Establish running of local commands
if ( islocalhost() )
{
  if ( ! defined_func("pread") ) audit(AUDIT_NOT_DETECT, "pread");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (! sock_g) audit(AUDIT_HOST_NOT, "able to connect via the provided SSH credentials.");
  info_t = INFO_SSH;
}

line = info_send_cmd(cmd:"/opt/sc4/support/bin/php -v");
if (empty_or_null(line)) line = info_send_cmd(cmd:"/opt/sc/support/bin/php -v");
if (empty_or_null(line)) audit(AUDIT_UNKNOWN_APP_VER, "PHP (within SecurityCenter)");

pattern = "PHP ([0-9.]+) ";
match = eregmatch(pattern:pattern, string:line);
if (isnull(match)) audit(AUDIT_UNKNOWN_APP_VER, "PHP (within SecurityCenter)");
version = match[1];

if (version =~ "^5\.4\.") fix = "5.4.43";
else if (version =~ "^5\.5\.") fix = "5.5.27";
else if (version =~ "^5\.6\.") fix = "5.6.11";
else fix = "5.4.43"; # default to known php release branch used in advisory

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report = '\n' +
    '\n  SecurityCenter version     : ' + sc_ver +
    '\n  SecurityCenter PHP version : ' + version +
    '\n  Fixed PHP version          : ' + fix +
    '\n';
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "PHP (within SecurityCenter)", version);
