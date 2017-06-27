#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K20225390.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(92667);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2017/03/14 16:13:00 $");

  script_cve_id("CVE-2015-2327", "CVE-2015-2328", "CVE-2015-3217", "CVE-2015-8380", "CVE-2015-8381", "CVE-2015-8382", "CVE-2015-8383", "CVE-2015-8384", "CVE-2015-8385", "CVE-2015-8386", "CVE-2015-8387", "CVE-2015-8388", "CVE-2015-8389", "CVE-2015-8390", "CVE-2015-8391", "CVE-2015-8392", "CVE-2015-8394", "CVE-2015-8395");
  script_bugtraq_id(75018);
  script_osvdb_id(109038, 109910, 122901, 125775, 125843, 126620, 130785, 131055, 131057, 131058, 131059, 131060, 131061, 131062, 131063, 131064, 131065, 131067, 131068);

  script_name(english:"F5 Networks BIG-IP : Multiple PCRE vulnerabilities (K20225390)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2015-8395 PCRE before 8.38 mishandles certain references, which
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via a crafted regular expression, as
demonstrated by a JavaScript RegExp object encountered by Konqueror, a
related issue to CVE-2015-8384 and CVE-2015-8392.

CVE-2015-8394 PCRE before 8.38 mishandles the (?() and (?(R)
conditions, which allows remote attackers to cause a denial of service
(integer overflow) or possibly have unspecified other impact via a
crafted regular expression, as demonstrated by a JavaScript RegExp
object encountered by Konqueror.

CVE-2015-8392 PCRE before 8.38 mishandles certain instances of the (?|
substring, which allows remote attackers to cause a denial of service
(unintended recursion and buffer overflow) or possibly have
unspecified other impact via a crafted regular expression, as
demonstrated by a JavaScript RegExp object encountered by Konqueror, a
related issue to CVE-2015-8384 and CVE-2015-8395.

CVE-2015-8391 The pcre_compile function in pcre_compile.c in PCRE
before 8.38 mishandles certain [: nesting, which allows remote
attackers to cause a denial of service (CPU consumption) or possibly
have unspecified other impact via a crafted regular expression, as
demonstrated by a JavaScript RegExp object encountered by Konqueror.

CVE-2015-8390 PCRE before 8.38 mishandles the [: and \\ substrings in
character classes, which allows remote attackers to cause a denial of
service (uninitialized memory read) or possibly have unspecified other
impact via a crafted regular expression, as demonstrated by a
JavaScript RegExp object encountered by Konqueror.

CVE-2015-8389 PCRE before 8.38 mishandles the /(?:|a|){100}x/ pattern
and related patterns, which allows remote attackers to cause a denial
of service (infinite recursion) or possibly have unspecified other
impact via a crafted regular expression, as demonstrated by a
JavaScript RegExp object encountered by Konqueror.

CVE-2015-8388 PCRE before 8.38 mishandles the
/(?=di(?<=(?1))|(?=(.))))/ pattern and related patterns with an
unmatched closing parenthesis, which allows remote attackers to cause
a denial of service (buffer overflow) or possibly have unspecified
other impact via a crafted regular expression, as demonstrated by a
JavaScript RegExp object encountered by Konqueror.

CVE-2015-8387 PCRE before 8.38 mishandles (?123) subroutine calls and
related subroutine calls, which allows remote attackers to cause a
denial of service (integer overflow) or possibly have unspecified
other impact via a crafted regular expression, as demonstrated by a
JavaScript RegExp object encountered by Konqueror.

CVE-2015-8386 PCRE before 8.38 mishandles the interaction of
lookbehind assertions and mutually recursive subpatterns, which allows
remote attackers to cause a denial of service (buffer overflow) or
possibly have unspecified other impact via a crafted regular
expression, as demonstrated by a JavaScript RegExp object encountered
by Konqueror.

CVE-2015-8385 PCRE before 8.38 mishandles the /(?|(\k'Pm')|(?'Pm'))/
pattern and related patterns with certain forward references, which
allows remote attackers to cause a denial of service (buffer overflow)
or possibly have unspecified other impact via a crafted regular
expression, as demonstrated by a JavaScript RegExp object encountered
by Konqueror.

CVE-2015-8384 PCRE before 8.38 mishandles the /(?J)(?'d'(?'d'\g{d}))/
pattern and related patterns with certain recursive back references,
which allows remote attackers to cause a denial of service (buffer
overflow) or possibly have unspecified other impact via a crafted
regular expression, as demonstrated by a JavaScript RegExp object
encountered by Konqueror, a related issue to CVE-2015-8392 and
CVE-2015-8395.

CVE-2015-8383 PCRE before 8.38 mishandles certain repeated conditional
groups, which allows remote attackers to cause a denial of service
(buffer overflow) or possibly have unspecified other impact via a
crafted regular expression, as demonstrated by a JavaScript RegExp
object encountered by Konqueror.

CVE-2015-8382 The match function in pcre_exec.c in PCRE before 8.37
mishandles the
/(?:((abcd))|(((?:(?:(?:(?:abc|(?:abcdef))))b)abcdefghi)abc)|((*ACCEPT
)))/ pattern and related patterns involving (*ACCEPT), which allows
remote attackers to obtain sensitive information from process memory
or cause a denial of service (partially initialized memory and
application crash) via a crafted regular expression, as demonstrated
by a JavaScript RegExp object encountered by Konqueror, aka
ZDI-CAN-2547.

CVE-2015-8381 The compile_regex function in pcre_compile.c in PCRE
before 8.38 and pcre2_compile.c in PCRE2 before 10.2x mishandles the
/(?J:(?|(:(?|(?'R')(\k'R')|((?'R')))H'Rk'Rf)|s(?'R'))))/ and
/(?J:(?|(:(?|(?'R')(\z(?|(?'R')(\k'R')|((?'R')))k'R')|((?'R')))H'Ak'Rf
)|s(?'R')))/ patterns, and related patterns with certain group
references, which allows remote attackers to cause a denial of service
(heap-based buffer overflow) or possibly have unspecified other impact
via a crafted regular expression, as demonstrated by a JavaScript
RegExp object encountered by Konqueror.

CVE-2015-8380 The pcre_exec function in pcre_exec.c in PCRE before
8.38 mishandles a // pattern with a \01 string, which allows remote
attackers to cause a denial of service (heap-based buffer overflow) or
possibly have unspecified other impact via a crafted regular
expression, as demonstrated by a JavaScript RegExp object encountered
by Konqueror.

CVE-2015-2328 PCRE before 8.36 mishandles the /((?(R)a|(?1)))+/
pattern and related patterns with certain recursion, which allows
remote attackers to cause a denial of service (segmentation fault) or
possibly have unspecified other impact via a crafted regular
expression, as demonstrated by a JavaScript RegExp object encountered
by Konqueror.

CVE-2015-2327 PCRE before 8.36 mishandles the /(((a\2)|(a*)\g<-1>))*/
pattern and related patterns with certain internal recursive back
references, which allows remote attackers to cause a denial of service
(segmentation fault) or possibly have unspecified other impact via a
crafted regular expression, as demonstrated by a JavaScript RegExp
object encountered by Konqueror.

CVE-2015-3217 PCRE 7.8 and 8.32 through 8.37, and PCRE2 10.10
mishandle group empty matches, which might allow remote attackers to
cause a denial of service (stack-based buffer overflow) via a crafted
regular expression, as demonstrated by
/^(?:(?(1)\\.|([^\\\\W_])?)+)+$/."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/#/article/K20225390"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K20225390."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"F5 Networks Local Security Checks");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version");

  exit(0);
}


include("f5_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/BIG-IP/version");
if ( ! version ) audit(AUDIT_OS_NOT, "F5 Networks BIG-IP");
if ( isnull(get_kb_item("Host/BIG-IP/hotfix")) ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/hotfix");
if ( ! get_kb_item("Host/BIG-IP/modules") ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/modules");

sol = "K20225390";
vmatrix = make_array();

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("12.0.0-12.1.0","11.3.0-11.6.1");
vmatrix["AFM"]["unaffected"] = make_list("12.1.1","11.6.1HF1","11.5.4HF2");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("12.0.0-12.1.0","11.4.0-11.6.1");
vmatrix["AM"]["unaffected"] = make_list("12.1.1","11.6.1HF1","11.5.4HF2");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("12.0.0-12.1.0","11.0.0-11.6.1","10.1.0-10.2.4");
vmatrix["APM"]["unaffected"] = make_list("12.1.1","11.6.1HF1","11.5.4HF2");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("12.0.0-12.1.0","11.0.0-11.6.1","10.1.0-10.2.4");
vmatrix["ASM"]["unaffected"] = make_list("12.1.1","11.6.1HF1","11.5.4HF2");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("12.0.0-12.1.0","11.0.0-11.6.1");
vmatrix["AVR"]["unaffected"] = make_list("12.1.1","11.6.1HF1","11.5.4HF2");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.0.0-11.6.1","10.1.0-10.2.4");
vmatrix["GTM"]["unaffected"] = make_list("11.6.1HF1","11.5.4HF2");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("12.0.0-12.1.0","11.0.0-11.6.1","10.1.0-10.2.4");
vmatrix["LC"]["unaffected"] = make_list("12.1.1","11.6.1HF1","11.5.4HF2");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("12.0.0-12.1.0","11.0.0-11.6.1","10.1.0-10.2.4");
vmatrix["LTM"]["unaffected"] = make_list("12.1.1","11.6.1HF1","11.5.4HF2");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("12.0.0-12.1.0","11.3.0-11.6.1");
vmatrix["PEM"]["unaffected"] = make_list("12.1.1","11.6.1HF1","11.5.4HF2");


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
