#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K13519.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(78134);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/04/07 15:07:04 $");

  script_cve_id("CVE-2006-0207", "CVE-2006-7243", "CVE-2007-3799", "CVE-2010-3710", "CVE-2010-3870", "CVE-2010-4697", "CVE-2011-0708", "CVE-2011-1470", "CVE-2011-2483", "CVE-2011-3182", "CVE-2011-3267", "CVE-2011-3268", "CVE-2011-4566", "CVE-2011-4885", "CVE-2012-0830");
  script_bugtraq_id(16220, 24268, 43926, 44605, 44951, 45952, 46365, 46969, 49241, 49249, 50907, 51193, 51830);
  script_osvdb_id(36855, 68597, 69230, 70606, 70607, 73623, 74738, 74739, 75200, 77446, 78819);

  script_name(english:"F5 Networks BIG-IP : Multiple PHP vulnerabilities (K13519)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"PHP has been cited with the following multiple vulnerabilities, which
may be locally exploitable on some F5 products :

CVE-2006-7243 PHP before 5.3.4 accepts the \0 character in a pathname,
which might allow context-dependent attackers to bypass intended
access restrictions by placing a safe file extension after this
character, as demonstrated by .php\0.jpg at the end of the argument to
the file_exists function.

CVE-2007-3799 The session_start function in ext/session in PHP 4.x up
to 4.4.7 and 5.x up to 5.2.3 allows remote attackers to insert
arbitrary attributes into the session cookie via special characters in
a cookie that is obtained from (1) PATH_INFO, (2) the session_id
function, and (3) the session_start function, which are not encoded or
filtered when the new session cookie is generated, a related issue to
CVE-2006-0207.

CVE-2010-3710 Stack consumption vulnerability in the filter_var
function in PHP 5.2.x through 5.2.14 and 5.3.x through 5.3.3, when
FILTER_VALIDATE_EMAIL mode is used, allows remote attackers to cause a
denial of service (memory consumption and application crash) via a
long e-mail address string.

CVE-2010-3870 The utf8_decode function in PHP before 5.3.4 does not
properly handle non-shortest form UTF-8 encoding and ill-formed
subsequences in UTF-8 data, which makes it easier for remote attackers
to bypass cross-site scripting (XSS) and SQL injection protection
mechanisms via a crafted string.

CVE-2010-4697 Use-after-free vulnerability in the Zend engine in PHP
before 5.2.15 and 5.3.x before 5.3.4 might allow context-dependent
attackers to cause a denial of service (heap memory corruption) or
have unspecified other impact via vectors related to use of __set,
__get, __isset, and __unset methods on objects accessed by a
reference.

CVE-2011-1470 The Zip extension in PHP before 5.3.6 allows
context-dependent attackers to cause a denial of service (application
crash) via a ziparchive stream that is not properly handled by the
stream_get_contents function.

CVE-2011-3182 PHP before 5.3.7 does not properly check the return
values of the malloc, calloc, and realloc library functions, which
allows context-dependent attackers to cause a denial of service (NULL
pointer dereference and application crash) or trigger a buffer
overflow by leveraging the ability to provide an arbitrary value for a
function argument, related to (1) ext/curl/interface.c, (2)
ext/date/lib/parse_date.c, (3) ext/date/lib/parse_iso_intervals.c, (4)
ext/date/lib/parse_tz.c, (5) ext/date/lib/timelib.c, (6)
ext/pdo_odbc/pdo_odbc.c, (7) ext/reflection/php_reflection.c, (8)
ext/soap/php_sdl.c, (9) ext/xmlrpc/libxmlrpc/base64.c, (10)
TSRM/tsrm_win32.c, and (11) the strtotime function.

CVE-2011-3267 PHP before 5.3.7 does not properly implement the
error_log function, which allows context-dependent attackers to cause
a denial of service (application crash) via unspecified vectors.

CVE-2011-3268 Buffer overflow in the crypt function in PHP before
5.3.7 allows context-dependent attackers to have an unspecified impact
via a long salt argument, a different vulnerability than
CVE-2011-2483.

CVE-2011-4566 Integer overflow in the exif_process_IFD_TAG function in
exif.c in the exif extension in PHP 5.4.0beta2 on 32-bit platforms
allows remote attackers to read the contents of arbitrary memory
locations or cause a denial of service via a crafted offset_val value
in an EXIF header in a JPEG file, a different vulnerability than
CVE-2011-0708.

CVE-2012-0830 The php_register_variable_ex function in php_variables.c
in PHP 5.3.9 allows remote attackers to execute arbitrary code via a
request containing a large number of variables, related to improper
handling of array variables. NOTE: this vulnerability exists because
of an incorrect fix for CVE-2011-4885."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/#/article/K13519"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K13519."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"F5 Networks Local Security Checks");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version", "Settings/ParanoidReport");

  exit(0);
}


include("f5_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/BIG-IP/version");
if ( ! version ) audit(AUDIT_OS_NOT, "F5 Networks BIG-IP");
if ( isnull(get_kb_item("Host/BIG-IP/hotfix")) ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/hotfix");
if ( ! get_kb_item("Host/BIG-IP/modules") ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/modules");

sol = "K13519";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("10.0.0-10.2.4","11.0.0-11.1.0");
vmatrix["APM"]["unaffected"] = make_list("11.2.0-11.4.0");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("10.0.0-10.2.4","11.0.0-11.1.0");
vmatrix["ASM"]["unaffected"] = make_list("11.2.0-11.4.0");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.0.0-11.1.0");
vmatrix["AVR"]["unaffected"] = make_list("11.2.0-11.4.0");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("10.0.0-10.2.4","11.0.0-11.1.0");
vmatrix["GTM"]["unaffected"] = make_list("11.2.0-11.4.0");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("10.0.0-10.2.4","11.0.0-11.1.0");
vmatrix["LC"]["unaffected"] = make_list("11.2.0-11.4.0");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("10.0.0-10.2.4","11.0.0-11.1.0");
vmatrix["LTM"]["unaffected"] = make_list("11.2.0-11.4.0");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("10.0.0-10.2.4","11.0.0-11.1.0");
vmatrix["PSM"]["unaffected"] = make_list("11.2.0-11.4.0");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("10.0.0-10.2.4","11.0.0-11.1.0");
vmatrix["WOM"]["unaffected"] = make_list("11.2.0-11.3.0");


if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  if (report_verbosity > 0) security_hole(port:0, extra:bigip_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = bigip_get_tested_modules();
  audit_extra = "For BIG-IP module(s) " + tested + ",";
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, "running any of the affected modules");
}
