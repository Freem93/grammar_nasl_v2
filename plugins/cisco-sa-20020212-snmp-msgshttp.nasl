#TRUSTED 81a1bff73411063bc9cfad51e8f4010c1db75908d544b10ecbd9b06bc90b1a83398022d5ada09693821ce7c10088ba17759dd89c661d076f038214a3d362147fd5f76912c7d66c8a4f98cbd91826738c1cee29889556f5dd92f8e28325ad28e808a9d6759d62e58da0fdeef45ca281c7a4412d4249c1fb88631955dbfe988af55b76991b071ffde1c4fe3e4dd3392b5f36a31467812c7f2cb737ac2c2ba4762c7032d3557df6d4d797eb0683226c90b2a6f1ea9030d5f8f698cd3ba606e3c8a970f48b2fd70cc54dcc4bb70ba6d79ae11936535f40d3d3cb33bf6f4644cf1456b9c3f7729d04c02bc45c586ee757ada1ad7a81ac3e6e61b9c1dd6af632554350efa60dabe4ad963f46bc3d1a2184478853666c6982dba39fb9ad679bd7f7486a6732dc2d0374ab313d2d7520ec4127df486e4a4443ba78c92d267cb603e8fbf85d732c2f4d17a6a4d24001c8a3b4618fcfe2a8c758a5b4b58f8df3c029d23cfad9776ecf5e6a1efce7be4151e7f477d5a003fb1ec0c06eeff3cf56795cb9b89c9d9b60f464ed131531d053dace95611e5e6000ba3af59aef9fa9b5d498cc3861ef26544e2193a4443df20cc5f370089715e4e71ae072e93f285caf643228f6af8fe4688eac365ae6c05e13edc65f8c189ccc89bce8307c59ab381e0c16ad89c602aae5d516f174b81290de0d2d46e814f94216b29b5726a4a3b4e7df4f0e347f
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/csa/cisco-sa-20020212-snmp-msgs.html

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48963);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2002-0012", "CVE-2002-0053");
 script_bugtraq_id(4088);
 script_osvdb_id(4850, 810);
 script_xref(name:"CERT-CC", value:"107186");
 script_xref(name:"CERT-CC", value:"854306");
 script_xref(name:"CERT-CC", value:"CA-2002-03");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdm63334");
 script_xref(name:"CISCO-BUG-ID", value:"CSCds53023");
 script_xref(name:"CISCO-BUG-ID", value:"CSCds87560");
 script_xref(name:"CISCO-BUG-ID", value:"CSCds89640");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt11503");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt14805");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt20091");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt41731");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt83999");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdu06427");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdu47447");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdu82770");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdu89682");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv04606");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv22261");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv43903");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv48776");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv48842");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv57565");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv60119");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv66527");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv73848");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdw03959");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdw62592");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdw62852");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdw63089");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdw65903");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdw68469");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdw72930");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdw78210");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdw89845");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdx14656");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdx27170");
 script_xref(name:"CISCO-BUG-ID", value:"CSCea29276");
 script_xref(name:"CISCO-BUG-ID", value:"CSCin01208");
 script_xref(name:"CISCO-BUG-ID", value:"CSCin01557");
 script_xref(name:"CISCO-BUG-ID", value:"CSCin01664");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20020212-snmp-msgs");
 script_name(english:"Malformed SNMP Message-Handling Vulnerabilities - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Multiple Cisco products contain vulnerabilities in the processing of
Simple Network Management Protocol (SNMP) messages. The vulnerabilities
can be repeatedly exploited to produce a denial of service. In most
cases, workarounds are available that may mitigate the impact. These
vulnerabilities are identified by various groups as VU#617947,
VU#107186, OUSPG #0100, CVE-2002-0012, and CVE-2002-0013.
');
 # this advisory isn't relevant - it's for cisco products that aren't IOS
 #script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?a1f3c81e");
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20020212-snmp-msgs
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbea5085");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00800945b4.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?4e6a4d8d");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20020212-snmp-msgs.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(264);
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/02/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/02/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2014 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
report_extra = "";
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

# Affected <= 10.3
if (
  version =~ "^[0-9]\." ||       # 0.x - 9.x
  version =~ "^10\.[0-3][^0-9]"  # 10.0 - 10.3
)
{
 report_extra = '\nNo updates are scheduled for releases 10.3 and earlier. Upgrade to a supported version\n'; flag++;
}
# Affected: 11.0
if (check_release(version: version,
                  patched: make_list("11.0(22b)") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 11.0BT
if (deprecated_version(version, "11.0BT")) {
 report_extra = '\nNo updates are scheduled for 11.0BT. Upgrade to a supported version\n'; flag++;
}
# Affected: 11.0NA
if (deprecated_version(version, "11.0NA")) {
 report_extra = '\nNo updates are scheduled for 11.0NA. Upgrade to a supported version\n'; flag++;
}
# Affected: 11.1
if (check_release(version: version,
                  patched: make_list("11.1(24b)") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 11.1AA
if (check_release(version: version,
                  patched: make_list("11.1(20)AA4") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 11.1CA
if (check_release(version: version,
                  patched: make_list("11.1(36)CA3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 11.1CC
if (check_release(version: version,
                  patched: make_list("11.1(36)CC5") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 11.1CT
if (check_release(version: version,
                  patched: make_list("11.1(28a)CT") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 11.1IA
if (check_release(version: version,
                  patched: make_list("11.1(28)IA2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 11.2
if (check_release(version: version,
                  patched: make_list("11.2(26d)") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 11.2BC
if (deprecated_version(version, "11.2BC")) {
 report_extra = '\nNo updates are scheduled for 11.2BC. Upgrade to a supported version\n'; flag++;
}
# Affected: 11.2F
if (deprecated_version(version, "11.2F")) {
 report_extra = '\nNo updates are scheduled for 11.2F. Upgrade to a supported version\n'; flag++;
}
# Affected: 11.2GS
if (check_release(version: version,
                  patched: make_list("11.2(19)GS8") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 11.2P
if (check_release(version: version,
                  patched: make_list("11.2(26)P4") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 11.2SA
if (check_release(version: version,
                  patched: make_list("11.2(8.10)SA6") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 11.2WA
if (deprecated_version(version, "11.2WA")) {
 report_extra = '\nNo updates are scheduled for 11.2WA. Upgrade to a supported version\n'; flag++;
}
# Affected: 11.2(4)XA
if (version == '11.2(4)XA') {
 report_extra = '\nUpdate to 11.2(4)XA2 or later\n'; flag++;
}
# Affected: 11.2(9)XA
if (version == '11.2(9)XA') {
 report_extra = '\nNo updates are scheduled for 11.2(9)XA. Upgrade to a supported version\n'; flag++;
}
# Affected: 11.3
if (check_release(version: version,
                  patched: make_list("11.3(11c)") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 11.3AA
if (deprecated_version(version, "11.3AA")) {
 report_extra = '\nNo updates are scheduled for 11.3AA. Upgrade to a supported version\n'; flag++;
}
# Affected: 11.3DA
if (deprecated_version(version, "11.3DA")) {
 report_extra = '\nNo updates are scheduled for 11.3DA. Upgrade to a supported version\n'; flag++;
}
# Affected: 11.3DB
if (check_release(version: version,
                  patched: make_list("11.3(9)DB3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 11.3DC
if (deprecated_version(version, "11.3DC")) {
 report_extra = '\nNo updates are scheduled for 11.3DC. Upgrade to a supported version\n'; flag++;
}
# Affected: 11.3HA
if (deprecated_version(version, "11.3HA")) {
 report_extra = '\nNo updates are scheduled for 11.3HA. Upgrade to a supported version\n'; flag++;
}
# Affected: 11.3MA
if (check_release(version: version,
                  patched: make_list("11.3(1)MA9") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 11.3NA
if (deprecated_version(version, "11.3NA")) {
 report_extra = '\nNo updates are scheduled for 11.3NA. Upgrade to a supported version\n'; flag++;
}
# Affected: 11.3T
if (check_release(version: version,
                  patched: make_list("11.3(11b)T2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 11.3(2)XA
if (version == '11.3(2)XA') {
 report_extra = '\nNo updates are scheduled for 11.3(2)XA. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.0
if (check_release(version: version,
                  patched: make_list("12.0(2b)", "12.0(3d)", "12.0(4b)", "12.0(5a)", "12.0(6b)", "12.0(7a)", "12.0(8a)", "12.0(9a)", "12.0(10a)", "12.0(11a)", "12.0(12a)", "12.0(13a)", "12.0(14a)", "12.0(15a)", "12.0(16a)", "12.0(17a)", "12.0(18b)", "12.0(19a)", "12.0(20a)", "12.0(21a)", "12.0(22)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0DA
if (deprecated_version(version, "12.0DA")) {
 report_extra = '\nNo updates are scheduled for 12.0DA. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.0DB
if (check_release(version: version,
                  patched: make_list("12.0(7)DB2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0DC
if (check_release(version: version,
                  patched: make_list("12.0(7)DC1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(8)S1", "12.0(9)S8", "12.0(10)S7", "12.0(11)S6", "12.0(12)S3", "12.0(13)S6", "12.0(14)S7", "12.0(15)S6", "12.0(16)S8", "12.0(17)S4", "12.0(18)S5", "12.0(19)S2", "12.0(21)S1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0SC
if (check_release(version: version,
                  patched: make_list("12.0(15)SC1", "12.0(16)SC3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0SL
if (check_release(version: version,
                  patched: make_list("12.0(17)SL6", "12.0(19)SL4") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0SP
if (check_release(version: version,
                  patched: make_list("12.0(20)SP1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(11)ST4", "12.0(14)ST3", "12.0(16)ST1", "12.0(17)ST5", "12.0(18)ST1", "12.0(19)ST2", "12.0(20)ST2"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0(10)SX
if (version == '12.0(10)SX') {
 report_extra = '\nNo updates are scheduled for 12.0(10)SX. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.0SX
if (check_release(version: version,
                  patched: make_list("12.0(21)SX") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0T
if (check_release(version: version,
                  patched: make_list("12.0(7)T2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0W5
if (
  version =~ 'W5' && # avoid flagging releases like W4, assuming they even exist
  check_release(version: version, patched: make_list("12.0(10)W5(18h)", "12.0(16)W5(21c)", "12.0(18)W5(22b)", "12.0(20)W5(24a)") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0WC
if (check_release(version: version,
                  patched: make_list("12.0(5)WC2b", "12.0(5)WC3b") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0(5)WC2, 12.0(5.3)WC1, and 12.0(5.4)WC1 for 2950 only
if (
  version == '12.0(5)WC2' ||
  version == '12.0(5.3)WC1' ||
  version == '12.0(5.4)WC1'
) {
 report_extra = '\nUpgrade to 12.1(6)EA2b or later\n'; flag++;
}
# Affected: 12.0(13)WT6(1)
if (version == '12.0(13)WT6(1)') {
 report_extra = '\nNo updates are scheduled for 12.0(13)WT6(1). Upgrade to a supported version\n'; flag++;
}
# Affected: 12.0WX (12.0(4a)WX5(11a))
if (version == '12.0(4a)WX5(11a)') {
 report_extra = '\nUpgrade to 12.0(20)W5(24a) or later\n'; flag++;
}
# Affected: 12.0WX (12.0(7)WX5(15a))
if (version == '12.0(7)WX5(15a)') {
 report_extra = '\nUpgrade to 12.0(18)W5(22b) or later\n'; flag++;
}
# Affected: 12.0WX
if (check_release(version: version,
                  patched: make_list("12.0(20)W5(24a)") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0(1)XA
if (version == '12.0(1)XA') {
 report_extra = '\nNo updates are scheduled for 12.0(1)XA. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.0(1)XB
if (version == '12.0(1)XB') {
 report_extra = '\nNo updates are scheduled for 12.0(1)XB. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.0(2)XC
if (version == '12.0(2)XC') {
 report_extra = '\nNo updates are scheduled for 12.0(2)XC. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.0(2)XD
if (version == '12.0(2)XD') {
 report_extra = '\nNo updates are scheduled for 12.0(2)XD. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.0(1)XE
if (version == '12.0(1)XE') {
 report_extra = '\nNo updates are scheduled for 12.0(1)XE. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.0(2)XE
if (version == '12.0(2)XE') {
 report_extra = '\nUpdate to 12.0(2)XE4 or later.\n'; flag++;
}
# Affected: 12.0(3)XE
if (version == '12.0(3)XE') {
 report_extra = '\nNo updates are scheduled for 12.0(3)XE. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.0(4)XE
if (version == '12.0(4)XE') {
 report_extra = '\nUpdate to 12.0(4)XE2 or later.\n'; flag++;
}
# Affected: 12.0(5)XE
if (version == '12.0(5)XE') {
 report_extra = '\nUpdate to 12.0(5)XE8 or later.\n'; flag++;
}
# Affected: 12.0(7)XE
if (version == '12.0(7)XE') {
 report_extra = '\nUpdate to 12.0(7)XE2 or later.\n'; flag++;
}
# Affected: 12.0(3)XG
if (version == '12.0(3)XG') {
 report_extra = '\nNo updates are scheduled for 12.0(3)XG. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.0(2)XH
if (version == '12.0(2)XH') {
 report_extra = '\nNo updates are scheduled for 12.0(2)XH. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.0(4)XH
if (version == '12.0(4)XH') {
 report_extra = '\nNo updates are scheduled for 12.0(4)XH. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.0(4)XI
if (version == '12.0(4)XI') {
 report_extra = '\nNo updates are scheduled for 12.0(4)XI. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.0(4)XJ
if (version == '12.0(4)XJ') {
 report_extra = '\nNo updates are scheduled for 12.0(4)XJ. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.0(5)XK
if (version == '12.0(5)XK') {
 report_extra = '\nUpdate to 12.0(5)XK2 or later\n'; flag++;
}
# Affected: 12.0(7)XK
if (version == '12.0(7)XK') {
 report_extra = '\nUpdate to 12.0(7)XK3 or later\n'; flag++;
}
# Affected: 12.0(4)XL
if (version == '12.0(4)XL') {
 report_extra = '\nNo updates are scheduled for 12.0(4)XL. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.0(4)XM
if (version == '12.0(4)XM') {
 report_extra = '\nUpdate to 12.0(4)XM1 or later\n'; flag++;
}
# Affected: 12.0(5)XN
if (version == '12.0(5)XN') {
 report_extra = '\nUpdate to 12.0(5)XN1 or later\n'; flag++;
}
# Affected: 12.0(5)XP and 12.0(5.1)XP, 12.0(5)XU and 12.0(5.2)XU
if (
  version == '12.0(5)XP' || version == '12.0(5)XP1' ||
  version == '12.0(5)XU' || version == '12.0(5)XU2'
) {
 report_extra = '\nUpdate to 12.0(5)WC3b or later\n'; flag++;
}
# Affected: 12.0(4)XT
if (version == '12.0(5)XT') {
 report_extra = '\nNo updates are scheduled for 12.0(5)XT. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.0(7)XV
if (version == '12.0(7)XV') {
 report_extra = '\nNo updates are scheduled for 12.0(7)XV. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1
if (check_release(version: version,
                  patched: make_list("12.1(1c)", "12.1(2b)", "12.1(3b)", "12.1(4a)", "12.1(5e)", "12.1(6a)", "12.1(7b)", "12.1(8c)", "12.1(9a)", "12.1(10a)", "12.1(11b)", "12.1(12b)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1AA
if (check_release(version: version,
                  patched: make_list("12.1(8)AA1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1CX
if (version == '12.1(4)CX' || version == '12.1(7)CX1') {
 report_extra = '\nNo updates are scheduled for 12.1(4)CX or 12.1(7)CX1. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1DA
if (check_release(version: version,
                  patched: make_list("12.1(7)DA3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1DB
if (check_release(version: version,
                  patched: make_list("12.1(1)DB2", "12.1(3)DB1", "12.1(4)DB2", "12.1(5)DB1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1DC
if (check_release(version: version,
                  patched: make_list("12.1(1)DC2", "12.1(3)DC2", "12.1(4)DC3", "12.1(5)DC2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(1)E5", "12.1(1)E6", "12.1(2)E2", "12.1(3a)E7", "12.1(4)E3", "12.1(5c)E12", "12.1(6)E8", "12.1(7a)E5", "12.1(7a)E6", "12.1(8b)E9", "12.1(9)E3", "12.1(10)E4", "12.1(3a)E7", "12.1(3a)E8") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1(6)EA2
if (version == '12.1(6)EA2') {
 report_extra = '\nUpdate to 12.1(3a)E8 or later\n'; flag++;
}
# Affected: 12.1(4)EA1e
if (version == '12.1(4)EA1e') {
 report_extra = '\nUpdate to 12.1(6)EA2b or later\n'; flag++;
}
# Affected: 12.1(6)EA1
if (version == '12.1(6)EA1') {
 report_extra = '\nUpdate to 12.1(8)EA1c or later\n'; flag++;
}
# Affected: 12.1EC
if (check_release(version: version,
                  patched: make_list("12.1(8)EC1", "12.1(9)EC1", "12.1(10)EC1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1(8a)EW
if (version == '12.1(8a)EW') {
 report_extra = '\nUpdate to 12.1(8a)EW1 or later\n'; flag++;
}
# Affected: 12.1(1)EX
if (version == '12.1(1)EX') {
 report_extra = '\nUpdate to 12.1(1)EX1 or later\n'; flag++;
}
# Affected: 12.1(5)EX
if (version == '12.1(5)EX') {
 report_extra = '\nUpdate to 12.1(5c)EX3 or later\n'; flag++;
}
# Affected: 12.1(6)EX
if (version == '12.1(6)EX') {
 report_extra = '\nNo updates are scheduled for 12.1(6)EX. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1(8a)EX
if (version == '12.1(8a)EX') {
 report_extra = '\nUpdate to 12.1(8b)EX4 or later\n'; flag++;
}
# Affected: 12.1(9)EX
if (version == '12.1(9)EX') {
 report_extra = '\nUpdate to 12.1(9)EX3 or later\n'; flag++;
}
# Affected: 12.1(10)EX
if (version == '12.1(10)EX') {
 report_extra = '\nUpdate to 12.1(10)EX or later\n'; flag++;  # 12.1(10)EX is obviously wrong, but that's what the advisory says
}
# Affected: 12.1(5)EY
if (version == '12.1(5)EY') {
 report_extra = '\nUpdate to 12.1(5)EY2 or later\n'; flag++;
}
# Affected: 12.1(6)EY
if (version == '12.1(6)EY') {
 report_extra = '\nUpdate to 12.1(6)EY1 or later\n'; flag++;
}
# Affected: 12.1(7a)EY
if (version == '12.1(7a)EY') {
 report_extra = '\nUpdate to 12.1(7a)EY3 or later\n'; flag++;
}
# Affected: 12.1T
if (check_release(version: version,
                  patched: make_list("12.1(5)T12") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1(1)XA
if (version == '12.1(1)XA') {
 report_extra = '\nNo updates are scheduled for 12.1(1)XA. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1(1)XB
if (version == '12.1(1)XB') {
 report_extra = '\nNo updates are scheduled for 12.1(1)XB. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1(1)XC
if (version == '12.1(1)XC') {
 report_extra = '\nUpdate to 12.1(1)XC1 or later\n'; flag++;
}
# Affected: 12.1(1)XD
if (version == '12.1(1)XD') {
 report_extra = '\nNo updates are scheduled for 12.1(1)XD. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1(1)XE
if (version == '12.1(1)XE') {
 report_extra = '\nUpdate to 12.1(1)XE1 or later\n'; flag++;
}
# Affected: 12.1(2)XF
if (version == '12.1(2)XF') {
 report_extra = '\nUpdate to 12.1(2)XF5 or later\n'; flag++;
}
# Affected: 12.1(3)XG
if (version == '12.1(3)XG') {
 report_extra = '\nUpdate to 12.1(3)XG6 or later\n'; flag++;
}
# Affected: 12.1(2a)XH
if (version == '12.1(2a)XH') {
 report_extra = '\nNo updates are scheduled for 12.1(2a)XH. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1(3)XI
if (version == '12.1(3)XI') {
 report_extra = '\nUpdate to 12.1(3a)XI8 or later\n'; flag++;
}
# Affected: 12.1(3)XJ
if (version == '12.1(3)XJ') {
 report_extra = '\nNo updates are scheduled for 12.1(3)XJ. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1(3)XL
if (version == '12.1(3)XL') {
 report_extra = '\nNo updates are scheduled for 12.1(3)XL. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1(5)XM
if (version == '12.1(5)XM') {
 report_extra = '\nUpdate to 12.1(5)XM7 or later\n'; flag++;
}
# Affected: 12.1(3)XP
if (version == '12.1(3)XP') {
 report_extra = '\nNo updates are scheduled for 12.1(3)XP. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1(3)XQ
if (version == '12.1(3)XQ') {
 report_extra = '\nNo updates are scheduled for 12.1(3)XQ. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1(5)XR
if (version == '12.1(5)XR') {
 report_extra = '\nUpdate to 12.1(5)XR2 or later\n'; flag++;
}
# Affected: 12.1(3)XS, 12.1(5)XS
if (version == '12.1(3)XS' || version == '12.1(5)XS') {
 report_extra = '\nNo updates are scheduled for 12.1(3)XS or 12.1(5)XS. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1(3)XT
if (version == '12.1(3)XT') {
 report_extra = '\nNo updates are scheduled for 12.1(3)XT. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1(5)XU
if (version == '12.1(5)XU') {
 report_extra = '\nNo updates are scheduled for 12.1(5)XU. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1(5)XV
if (version == '12.1(5)XV') {
 report_extra = '\nUpdate to 12.1(5)XV4 or later\n'; flag++;
}
# Affected: 12.1(3)XW
if (version == '12.1(3)XW') {
 report_extra = '\nNo updates are scheduled for 12.1(3)XW. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1(5)XX
if (version == '12.1(5)XX') {
 report_extra = '\nNo updates are scheduled for 12.1(5)XX. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1(5)YA
if (version == '12.1(5)YA') {
 report_extra = '\nUpdate to 12.1(5)YA2 or later\n'; flag++;
}
# Affected: 12.1(5)YB
if (version == '12.1(5)YB') {
 report_extra = '\nUpdate to 12.1(5)YB5 or later\n'; flag++;
}
# Affected: 12.1(5)YC
if (version == '12.1(5)YC') {
 report_extra = '\nUpdate to 12.1(5)YC2 or later\n'; flag++;
}
# Affected: 12.1(5)YD
if (version == '12.1(5)YD') {
 report_extra = '\nUpdate to 12.1(5)YD6 or later\n'; flag++;
}
# Affected: 12.1(5)YE
if (version == '12.1(5)YE') {
 report_extra = '\nNo updates are scheduled for 12.1(5)YE. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1(5)YF
if (version == '12.1(5)YF') {
 report_extra = '\nUpdate to 12.1(5)YF4 or later\n'; flag++;
}
# Affected: 12.1(5)YH
if (version == '12.1(5)YH') {
 report_extra = '\nUpdate to 12.1(5)YH3 or later\n'; flag++;
}
# Affected: 12.1(5)YI
if (version == '12.1(5)YI') {
 report_extra = '\nUpdate to 12.1(5)YI2 or later\n'; flag++;
}
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(1d)", "12.2(3d)", "12.2(5d)", "12.2(6c)", "12.2(7a)") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2B
if (check_release(version: version,
                  patched: make_list("12.2(2)B4", "12.2(4)B2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2BC
if (check_release(version: version,
                  patched: make_list("12.2(4)BC1a") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2BY
if (check_release(version: version,
                  patched: make_list("12.2(2)BY2", "12.2(2)BY3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2DA
if (check_release(version: version,
                  patched: make_list("12.2(1b)DA1", "12.2(5)DA1"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2DD
if (check_release(version: version,
                  patched: make_list("12.2(2)DD3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2DX
if (check_release(version: version,
                  patched: make_list("12.2(1)DX1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2MB
if (check_release(version: version,
                  patched: make_list("12.2(4)MB3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2MX
if (check_release(version: version,
                  patched: make_list("12.2(4)MX1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2T
if (check_release(version: version,
                  patched: make_list("12.2(2)T4", "12.2(4)T3"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2(1)XA
if (version == '12.2(1)XA') {
 report_extra = '\nUpdate to 12.2(2)XA5 or later\n'; flag++;
}
# Affected: 12.2(2)XB
if (version == '12.2(2)XB') {
 report_extra = '\nUpdate to 12.2(2)XB3 or later\n'; flag++;
}
# Affected: 12.2(1a)XC
if (version == '12.2(1a)XC') {
 report_extra = '\nNo updates are scheduled for 12.2(1a)XC. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.2(2)XC
if (version == '12.2(2)XC') {
 report_extra = '\nNo updates are scheduled for 12.2(2)XC. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.2(1)XD
if (version == '12.2(1)XD') {
 report_extra = '\nUpdate to 12.2(1)XD3 or later\n'; flag++;
}
# Affected: 12.2(1)XE
if (version == '12.2(1)XE') {
 report_extra = '\nUpdate to 12.2(1)XE2 or later\n'; flag++;
}
# Affected: 12.2(1)XF1
if (version == '12.2(1)XF1') {
 report_extra = '\nNo updates are scheduled for 12.2(1)XF1. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.2(2)XF
if (version == '12.2(2)XF') {
 report_extra = '\nNo updates are scheduled for 12.2(2)XF. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.2(4)XF
if (version == '12.2(4)XF') {
 report_extra = '\nNo updates are scheduled for 12.2(4)XF. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.2(2)XG
if (version == '12.2(2)XG') {
 report_extra = '\nUpdate to 12.2(2)XG1 or later\n'; flag++;
}
# Affected: 12.2(2)XH
if (version == '12.2(2)XH') {
 report_extra = '\nUpdate to 12.2(2)XH2 or later\n'; flag++;
}
# Affected: 12.2(2)XI
if (version == '12.2(2)XI') {
 report_extra = '\nUpdate to 12.2(2)XI1 or later\n'; flag++;
}
# Affected: 12.2(2)XJ
if (version == '12.2(2)XJ') {
 report_extra = '\nUpdate to 12.2(2)XJ1 or later\n'; flag++;
}
# Affected: 12.2(2)XK
if (version == '12.2(2)XK') {
 report_extra = '\nUpdate to 12.2(2)XK2 or later\n'; flag++;
}
# Affected: 12.2(4)XL
if (version == '12.2(4)XL') {
 report_extra = '\nUpdate to 12.2(4)XL3 or later\n'; flag++;
}
# Affected: 12.2(4)XM
if (version == '12.2(4)XM') {
 report_extra = '\nUpdate to 12.2(4)XM2 or later\n'; flag++;
}
# Affected: 12.2(2)XN
if (version == '12.2(2)XN') {
 report_extra = '\nUpdate to 12.2(2)XN or later\n'; flag++;  # 12.2(2)XN is obviously wrong, but it's what the advisory says
}
# Affected: 12.2(2)XQ
if (version == '12.2(2)XQ') {
 report_extra = '\nUpdate to 12.2(2)XQ2 or later\n'; flag++;
}
# Affected: 12.2(1)XS
if (version == '12.2(1)XS') {
 report_extra = '\nUpdate to 12.2(1)XS2 or later\n'; flag++;
}
# Affected: 12.2(2)XT
if (version == '12.2(2)XT') {
 report_extra = '\nUpdate to 12.2(2)XT2 or later\n'; flag++;
}
# Affected: 12.2(2)XU
if (version == '12.2(2)XU') {
 report_extra = '\nUpdate to 12.2(2)XU2 or later\n'; flag++;
}
# Affected: 12.2(4)XW
if (version == '12.2(4)XW') {
 report_extra = '\nUpdate to 12.2(4)XW1 or later\n'; flag++;
}
# Affected: 12.2(4)YA
if (version == '12.2(4)YA') {
 report_extra = '\nUpdate to 12.2(4)YA1 or later\n'; flag++;
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"snmp-server\s+enable", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

