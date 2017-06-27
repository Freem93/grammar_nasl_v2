#TRUSTED 7aa7a59997a74a0f6dc498f851e8d05947f837583644b2a2e2267df81f5ffdd3a2e37fcca481556d13da865d89d5b849a4b88cf0ddfa5fe5511bcbb9049058fa94032a3f9c634d87c8e674655a463988c0884125d6c2e03c65688b26a0c7f4cd8af1ce601bb51e077d52039933e80ab1fb2bd25e98c54a0e559a2445f3a12b4bcabf87019665f1cd78d7c7a891b3cf4ea63fbed832d9c6285b6afcc7208c3f7eebf0d97146bbab773a0c6fbaed28feb8350992819c6159a85023f78a6ec0f0925e0cc43095367c21e358b4a4c7c3bee15da7da3611482390717c1120766d85710754ca4037676f3289da5edded5dff9ad5c23f1e1a05267dd8d0aff284eb1c9352d30acae5d90092c110e0125b24ff0abc0cad3df0d16d37f488350599782816c424de741a787d49a25a74c3399c6782edd9241ef7254a97fcecf33fa5e5fd2eea72ec3453137a79b4332934167a49969c73aefd8a392f65a26f908a544b5ab9edd4f47ee53c5f35dfb691f40b8b701027ae235f2eeb323eb47dbc560a5c1384b91106e7d95381e28919b2b50c050a7e88686ee342f7daf010fdeff044ce3b84a4ab056e673c1f533f494e8833bf9bf33a8a9ef287098f7f599638a1b4ad2c6dee60383370e16898d26869e4ae7b96cc88e4753b2f56259463bcd9c7c92bc61335116f3dfd82d6f52c5fe56a43f069b1cd764d0a6fd471fad4a8f181edbfb168
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85566);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/03");

  script_cve_id(
    "CVE-2006-7243",
    "CVE-2015-2325",
    "CVE-2015-2326",
    "CVE-2015-4024",
    "CVE-2015-4025"
  );
  script_bugtraq_id(
    44951,
    74903,
    74904,
    75174,
    75175
  );
  script_osvdb_id(
    70606,
    119870,
    119871,
    122127,
    122268
  );

  script_name(english:"Tenable SecurityCenter Multiple PHP Vulnerabilities (TNS-2015-06)");
  script_summary(english:"Checks the version of PHP in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The SecurityCenter application installed on the remote host is
affected by multiple vulnerabilities in the bundled version of PHP
that is prior to version 5.4.41. It is, therefore, affected by the
following vulnerabilities :

  - Multiple flaws exist related to using pathnames
    containing NULL bytes. A remote attacker can exploit
    these flaws, by combining the '\0' character with a safe
    file extension, to bypass access restrictions. This had
    been previously fixed but was reintroduced by a
    regression in versions 5.4+. (CVE-2006-7243,
    CVE-2015-4025)

  - Multiple heap buffer overflow conditions exist in the
    bundled Perl-Compatible Regular Expression (PCRE)
    library due to improper validation of user-supplied
    input to the compile_branch() and pcre_compile2()
    functions. A remote attacker can exploit these
    conditions to cause a heap-based buffer overflow,
    resulting in a denial of service condition or the
    execution of arbitrary code. (CVE-2015-2325,
    CVE-2015-2326)

  - A flaw exists in the multipart_buffer_headers() function
    in rfc1867.c due to improper handling of
    multipart/form-data in HTTP requests. A remote attacker
    can exploit this flaw to cause a consumption of CPU
    resources, resulting in a denial of service condition.
    (CVE-2015-4024)");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/security/tns-2015-06");
  script_set_attribute(attribute:"see_also", value:"https://secure.php.net/ChangeLog-5.php#5.4.41");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

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
if (! ereg(pattern:"^(4\.[6789]|5)\.", string:sc_ver)) audit(AUDIT_INST_VER_NOT_VULN, "SecurityCenter", sc_ver);

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
if (!line) line = info_send_cmd(cmd:"/opt/sc/support/bin/php -v");
if (!line) audit(AUDIT_UNKNOWN_APP_VER, "PHP (within SecurityCenter)");

pattern = "PHP ([0-9.]+) ";
match = eregmatch(pattern:pattern, string:line);
if (isnull(match)) audit(AUDIT_UNKNOWN_APP_VER, "PHP (within SecurityCenter)");
version = match[1];

if (version =~ "^5\.4\.") fix = "5.4.41";
else if (version =~ "^5\.5\.") fix = "5.5.25";
else if (version =~ "^5\.6\.") fix = "5.6.9";
else fix = "5.4.41"; # default to known php release branch used in advisory

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
