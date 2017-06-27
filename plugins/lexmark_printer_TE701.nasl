#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86426);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/20 23:02:22 $");

  script_cve_id("CVE-2015-0204", "CVE-2015-1637");
  script_bugtraq_id(71936, 72965);
  script_osvdb_id(116794, 119106);
  script_xref(name:"CERT", value:"243585");

  script_name(english:"Lexmark Printer config.html Administrator Authentication Bypass (FREAK)");
  script_summary(english:"Checks the version of a Lexmark printer.");

  script_set_attribute(attribute:"synopsis", value:
"The remote printer is affected by a security bypass vulnerability
known as FREAK.");
  script_set_attribute(attribute:"description", value:
"According to its firmware version, the remote Lexmark printer is
affected by a security feature bypass vulnerability, known as FREAK
(Factoring attack on RSA-EXPORT Keys), due to the support of weak
EXPORT_RSA cipher suites with keys less than or equal to 512 bits. A
man-in-the-middle attacker may be able to downgrade the SSL/TLS
connection to use EXPORT_RSA cipher suites which can be factored in a
short amount of time, allowing the attacker to intercept and decrypt
the traffic.");
  # http://support.lexmark.com/index?modifiedDate=04%2F20%2F15&page=content&actp=LIST_RECENT&id=TE701&locale=EN&userlocale=EN_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60f299d0");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a fixed release as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:cs31x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:cs41x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:cs51x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:cx310");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:cx410");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:cx510");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:xc2132");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:ms310");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:ms312");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:ms315");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:ms410");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:ms415");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:ms51x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:ms610dn");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:ms610dtn");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:m1145");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:m3150dn");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:ms610de");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:ms610dte");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:m3150");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:ms71x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:ms810n");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:ms810dn");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:ms810dtn");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:ms811");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:ms812dn");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:ms812dtn");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:m5163dn");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:ms810de");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:m5155");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:m5163");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:ms812de");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:m5170");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:ms91x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:mx310");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:mx410");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:mx510");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:mx511");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:xm1145");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:mx610");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:mx611");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:xm3150");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:mx71x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:mx81x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:xm51xx");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:xm71xx");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:mx91x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:mx6500e");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:c746");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:c748");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:cs748");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:c79x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:cs796");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:c925");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:c95x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:x548");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:xs548");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:x74x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:xs748");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:x792");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:xs79x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:x925");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:xs925");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:x95x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:xs95x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:6500e");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:c734");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:c736");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:e46x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:t650");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:t652");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:t654");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:t656");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:w85x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:x46x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:x65x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:x73x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:x86x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:c54x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:e26x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:e36x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:x26x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:x36x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:x54x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:c52x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:c53x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:c77x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:c78x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:c92x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:c93x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:e45x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:t64x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:w84x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:x642");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:x644");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:x646");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:x64xef");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:x77x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:x78x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:x85x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:x94x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:n4000");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:n4050e");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:n7xxe");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("lexmark_printer_detect.nasl");
  script_require_keys("www/lexmark_printer/model", "www/lexmark_printer/base_ver");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

report_model   = get_kb_item_or_exit("www/lexmark_printer/model");
report_version = get_kb_item_or_exit("www/lexmark_printer/base_ver");

use_model = tolower(report_model - 'Lexmark ');
use_version = tolower(report_version);

if (report_version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "the remote Lexmark printer ("+report_model+")", 0);

# tolower(model regex),
# vuln regex
model_and_vuln_vers = make_array(
  # CS31x with LW41.VYL.P486 or previous
  "^cs31[0-9]$",
  "^lw41\.vyl\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # CS41x with LW41.VY2.P486 or previous
  "^cs41[0-9]$",
  "^lw41\.vy2\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # CS51x with LW41.VY4.P486 or previous
  "^cs51[0-9]$",
  "^lw41\.vy4\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # CX310 with LW41.GM2.P486 or previous
  "^cx310$",
  "^lw41\.gm2\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # CX410 with LW41.GM4.P486 or previous
  "^cx410$",
  "^lw41\.gm4\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # CX510 with LW41.GM7.P486 or previous
  "^cx510$",
  "^lw41\.gm7\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # XC2132 with LW41.GM7.P486 or previous
  "^xc2132$",
  "^lw41\.gm7\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MS310 with LW41.PRL.P486 or previous
  "^ms310$",
  "^lw41\.prl\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MS312 with LW41.PRL.P486 or previous
  "^ms312$",
  "^lw41\.prl\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MS315 with LW41.TL2.P486 or previous
  "^ms315$",
  "^lw41\.tl2\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MS410 with LW41.PRL.P486 or previous
  "^ms410$",
  "^lw41\.prl\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MS415 with LW41.TL2.P486 or previous
  "^ms415$",
  "^lw41\.tl2\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MS51x with LW41.PR2.P486 or previous
  "^ms51[0-9]$",
  "^lw41\.pr2\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MS610dn with LW41.PR2.P486 or previous
  "^ms610dn$",
  "^lw41\.pr2\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MS610dtn with LW41.PR2.P486 or previous
  "^ms610dtn$",
  "^lw41\.pr2\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # M1145 with LW41.PR2.P486 or previous
  "^m1145$",
  "^lw41\.pr2\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # M3150dn with LW41.PR2.P486 or previous
  "^m3150dn$",
  "^lw41\.pr2\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MS610de with LW41.PR4.P486 or previous
  "^ms610de$",
  "^lw41\.pr4\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MS610dte with LW41.PR4.P486 or previous
  "^ms610dte$",
  "^lw41\.pr4\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # M3150 with LW41.PR4.P486 or previous
  "^m3150$",
  "^lw41\.pr4\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MS71x with LW41.DN2.P486 or previous
  "^ms71[0-9]$",
  "^lw41\.dn2\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MS810n with LW41.DN2.P486 or previous
  "^ms810n$",
  "^lw41\.dn2\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MS810dn with LW41.DN2.P486 or previous
  "^ms810dn$",
  "^lw41\.dn2\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MS810dtn with LW41.DN2.P486 or previous
  "^ms810dtn$",
  "^lw41\.dn2\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MS811 with LW41.DN2.P486 or previous
  "^ms811$",
  "^lw41\.dn2\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MS812dn with LW41.DN2.P486 or previous
  "^ms812dn$",
  "^lw41\.dn2\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MS812dtn with LW41.DN2.P486 or previous
  "^ms812dtn$",
  "^lw41\.dn2\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # M5163dn with LW41.DN2.P486 or previous
  "^m5163dn$",
  "^lw41\.dn2\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MS810de with LW41.DN4.P486 or previous
  "^ms810de$",
  "^lw41\.dn4\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # M5155 with LW41.DN4.P486 or previous
  "^m5155$",
  "^lw41\.dn4\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # M5163 with LW41.DN4.P486 or previous
  "^m5163$",
  "^lw41\.dn4\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MS812de with LW41.DN7.P486 or previous
  "^ms812de$",
  "^lw41\.dn7\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # M5170 with LW41.DN7.P486 or previous
  "^m5170$",
  "^lw41\.dn7\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MS91x with LW41.SA.P486 or previous
  "^ms91[0-9]$",
  "^lw41\.sa\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MX310 with LW41.SB2.P486 or previous
  "^mx310$",
  "^lw41\.sb2\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MX410 with LW41.SB4.P486 or previous
  "^mx410$",
  "^lw41\.sb4\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MX510 with LW41.SB4.P486 or previous
  "^mx510$",
  "^lw41\.sb4\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MX511 with LW41.SB4.P486 or previous
  "^mx511$",
  "^lw41\.sb4\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # XM1145 with LW41.SB4.P486 or previous
  "^xm1145$",
  "^lw41\.sb4\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MX610 with LW41.SB7.P486 or previous
  "^mx610$",
  "^lw41\.sb7\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MX611 with LW41.SB7.P486 or previous
  "^mx611$",
  "^lw41\.sb7\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # XM3150 with LW41.SB7.P486 or previous
  "^xm3150$",
  "^lw41\.sb7\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MX71x with LW41.TU.P486 or previous
  "^mx71[0-9]$",
  "^lw41\.tu\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MX81x with LW41.TU.P486 or previous
  "^mx81[0-9]$",
  "^lw41\.tu\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # XM51xx with LW41.TU.P486 or previous
  "^xm51[0-9][0-9]$",
  "^lw41\.tu\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # XM71xx with LW41.TU.P486 or previous
  "^xm71[0-9][0-9]$",
  "^lw41\.tu\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MX91x with LW41.MG.P486 or previous
  "^mx91[0-9]$",
  "^lw41\.mg\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # MX6500e with LW41.JD.P486 or previous
  "^mx6500e$",
  "^lw41\.jd\.p([0-3][0-9][0-9]|4[0-7][0-9]|48[0-6])($|[^0-9])", 
  # C746 with LHS41.CM2.P476 or previous
  "^c746$",
  "^lhs41\.cm2\.p([0-3][0-9][0-9]|4[0-6][0-9]|47[0-6])($|[^0-9])", 
  # C748 with LHS41.CM4.P476 or previous
  "^c748$",
  "^lhs41\.cm4\.p([0-3][0-9][0-9]|4[0-6][0-9]|47[0-6])($|[^0-9])", 
  # CS748 with LHS41.CM4.P476 or previous
  "^cs748$",
  "^lhs41\.cm4\.p([0-3][0-9][0-9]|4[0-6][0-9]|47[0-6])($|[^0-9])", 
  # C79x with LHS41.HC.P476 or previous
  "^c79[0-9]$",
  "^lhs41\.hc\.p([0-3][0-9][0-9]|4[0-6][0-9]|47[0-6])($|[^0-9])", 
  # CS796 with LHS41.HC.P476 or previous
  "^cs796$",
  "^lhs41\.hc\.p([0-3][0-9][0-9]|4[0-6][0-9]|47[0-6])($|[^0-9])", 
  # C925 with LHS41.HV.P476 or previous
  "^c925$",
  "^lhs41\.hv\.p([0-3][0-9][0-9]|4[0-6][0-9]|47[0-6])($|[^0-9])", 
  # C95x with LHS41.TP.P476 or previous
  "^c95[0-9]$",
  "^lhs41\.tp\.p([0-3][0-9][0-9]|4[0-6][0-9]|47[0-6])($|[^0-9])", 
  # X548 with LHS41.VK.P476 or previous
  "^x548$",
  "^lhs41\.vk\.p([0-3][0-9][0-9]|4[0-6][0-9]|47[0-6])($|[^0-9])", 
  # XS548 with LHS41.VK.P476 or previous
  "^xs548$",
  "^lhs41\.vk\.p([0-3][0-9][0-9]|4[0-6][0-9]|47[0-6])($|[^0-9])", 
  # X74x with LHS41.NY.P476 or previous
  "^x74[0-9]$",
  "^lhs41\.ny\.p([0-3][0-9][0-9]|4[0-6][0-9]|47[0-6])($|[^0-9])", 
  # XS748 with LHS41.NY.P476 or previous
  "^xs748$",
  "^lhs41\.ny\.p([0-3][0-9][0-9]|4[0-6][0-9]|47[0-6])($|[^0-9])", 
  # X792 with LHS41.MR.P476 or previous
  "^x792$",
  "^lhs41\.mr\.p([0-3][0-9][0-9]|4[0-6][0-9]|47[0-6])($|[^0-9])", 
  # XS79x with LHS41.MR.P476 or previous
  "^xs79[0-9]$",
  "^lhs41\.mr\.p([0-3][0-9][0-9]|4[0-6][0-9]|47[0-6])($|[^0-9])", 
  # X925 with LHS41.HK.P476 or previous
  "^x925$",
  "^lhs41\.hk\.p([0-3][0-9][0-9]|4[0-6][0-9]|47[0-6])($|[^0-9])", 
  # XS925 with LHS41.HK.P476 or previous
  "^xs925$",
  "^lhs41\.hk\.p([0-3][0-9][0-9]|4[0-6][0-9]|47[0-6])($|[^0-9])", 
  # X95x with LHS41.TQ.P476 or previous
  "^x95[0-9]$",
  "^lhs41\.tq\.p([0-3][0-9][0-9]|4[0-6][0-9]|47[0-6])($|[^0-9])", 
  # XS95x with LHS41.TQ.P476 or previous
  "^xs95[0-9]$",
  "^lhs41\.tq\.p([0-3][0-9][0-9]|4[0-6][0-9]|47[0-6])($|[^0-9])", 
  # 6500e with LHS41.JR.P476 or previous
  "^6500e$",
  "^lhs41\.jr\.p([0-3][0-9][0-9]|4[0-6][0-9]|47[0-6])($|[^0-9])", 
  # C734 with LR.SK.P696 or previous
  "^c734$",
  "^lr\.sk\.p([0-5][0-9][0-9]|6[0-8][0-9]|69[0-6])($|[^0-9])", 
  # C736 with LR.SKE.P694 or previous
  "^c736$",
  "^lr\.ske\.p([0-5][0-9][0-9]|6[0-8][0-9]|69[0-4])($|[^0-9])", 
  # E46x with LR.LBH.P675 or previous
  "^e46[0-9]$",
  "^lr\.lbh\.p([0-5][0-9][0-9]|6[0-6][0-9]|67[0-5])($|[^0-9])", 
  # T650 with LR.JP.P684 or previous
  "^t650$",
  "^lr\.jp\.p([0-5][0-9][0-9]|6[0-7][0-9]|68[0-4])($|[^0-9])", 
  # T652 with LR.JP.P684 or previous
  "^t652$",
  "^lr\.jp\.p([0-5][0-9][0-9]|6[0-7][0-9]|68[0-4])($|[^0-9])", 
  # T654 with LR.JP.P684 or previous
  "^t654$",
  "^lr\.jp\.p([0-5][0-9][0-9]|6[0-7][0-9]|68[0-4])($|[^0-9])", 
  # T656 with LSJ.SJ.P044 or previous
  "^t656$",
  "^lsj\.sj\.p(0[0-3][0-9]|04[0-4])($|[^0-9])", 
  # W85x with LR.JB.P647 or previous
  "^w85[0-9]$",
  "^lr\.jb\.p([0-5][0-9][0-9]|6[0-3][0-9]|64[0-7])($|[^0-9])", 
  # X46x with LR.BS.P698 or previous
  "^x46[0-9]$",
  "^lr\.bs\.p([0-5][0-9][0-9]|6[0-8][0-9]|69[0-8])($|[^0-9])", 
  # X65x with LR.MN.P700 or previous
  "^x65[0-9]$",
  "^lr\.mn\.p([0-6][0-9][0-9]|700)($|[^0-9])", 
  # X73x with LR.FL.P698 or previous
  "^x73[0-9]$",
  "^lr\.fl\.p([0-5][0-9][0-9]|6[0-8][0-9]|69[0-8])($|[^0-9])", 
  # X86x with LP.SP.P700 or previous
  "^x86[0-9]$",
  "^lp\.sp\.p([0-6][0-9][0-9]|700)($|[^0-9])", 
  # C54x with LL.AS.P536 or previous
  "^c54[0-9]$",
  "^ll\.as\.p([0-4][0-9][0-9]|5[0-2][0-9]|53[0-6])($|[^0-9])", 
  # E26x with LL.LBL.P541 or previous
  "^e26[0-9]$",
  "^ll\.lbl\.p([0-4][0-9][0-9]|5[0-3][0-9]|54[0-1])($|[^0-9])", 
  # E36x with LL.LBM.P541 or previous
  "^e36[0-9]$",
  "^ll\.lbm\.p([0-4][0-9][0-9]|5[0-3][0-9]|54[0-1])($|[^0-9])", 
  # X26x with LL.BZ.P546 or previous
  "^x26[0-9]$",
  "^ll\.bz\.p([0-4][0-9][0-9]|5[0-3][0-9]|54[0-6])($|[^0-9])", 
  # X36x with LL.BZ.P546 or previous
  "^x36[0-9]$",
  "^ll\.bz\.p([0-4][0-9][0-9]|5[0-3][0-9]|54[0-6])($|[^0-9])", 
  # X54x with LL.EL.P546 or previous
  "^x54[0-9]$",
  "^ll\.el\.p([0-4][0-9][0-9]|5[0-3][0-9]|54[0-6])($|[^0-9])", 
  # C52x with LS.FA.P152 or previous
  "^c52[0-9]$",
  "^ls\.fa\.p(0[0-9][0-9]|1[0-4][0-9]|15[0-2])($|[^0-9])", 
  # C53x with LS.SW.P071 or previous
  "^c53[0-9]$",
  "^ls\.sw\.p(0[0-6][0-9]|07[0-1])($|[^0-9])", 
  # C77x with LC.CM.P503 or previous
  "^c77[0-9]$",
  "^lc\.cm\.p([0-4][0-9][0-9]|50[0-3])($|[^0-9])", 
  # C78x with LC.IO.P190 or previous
  "^c78[0-9]$",
  "^lc\.io\.p(0[0-9][0-9]|1[0-8][0-9]|190)($|[^0-9])", 
  # C92x with LS.TA.P154 or previous
  "^c92[0-9]$",
  "^ls\.ta\.p(1[0-4][0-9]|15[0-4])($|[^0-9])", 
  # C93x with LC.JO.P095 or previous
  "^c93[0-9]$",
  "^lc\.jo\.p(0[0-8][0-9]|09[0-5])($|[^0-9])", 
  # E45x with LM.SZ.P124 or previous
  "^e45[0-9]$",
  "^lm\.sz\.p(0[0-9][0-9]|1[0-1][0-9]|12[0-4])($|[^0-9])", 
  # T64x with LS.ST.P353 or previous
  "^t64[0-9]$",
  "^ls\.st\.p([0-2][0-9][0-9]|3[0-4][0-9]|35[0-3])($|[^0-9])", 
  # W84x with LS.HA.P254 or previous
  "^w84[0-9]$",
  "^ls\.ha\.p([0-1][0-9][0-9]|2[0-4][0-9]|25[0-4])($|[^0-9])", 
  # X642 with LC2.MB.P318 or previous
  "^x642$",
  "^lc2\.mb\.p([0-2][0-9][0-9]|3[0-1][0-9])($|[^0-9])", 
  # X644 with LC2.MC.P377 or previous
  "^x644$",
  "^lc2\.mc\.p([0-2][0-9][0-9]|3[0-6][0-9]|37[0-7])($|[^0-9])", 
  # X646 with LC2.MC.P377 or previous
  "^x646$",
  "^lc2\.mc\.p([0-2][0-9][0-9]|3[0-6][0-9]|37[0-7])($|[^0-9])", 
  # X64xef with LC2.TI.P329 or previous
  "^x64[0-9]ef$",
  "^lc2\.ti\.p([0-2][0-9][0-9]|3[0-1][0-9]|32[0-9])($|[^0-9])", 
  # X77x with LC2.TR.P291 or previous
  "^x77[0-9]$",
  "^lc2\.tr\.p([0-1][0-9][0-9]|2[0-8][0-9]|29[0-1])($|[^0-9])", 
  # X78x with LC2.TO.P339 or previous
  "^x78[0-9]$",
  "^lc2\.to\.p([0-2][0-9][0-9]|3[0-2][0-9]|33[0-9])($|[^0-9])", 
  # X85x with LC4.BE.P491 or previous
  "^x85[0-9]$",
  "^lc4\.be\.p([0-3][0-9][0-9]|4[0-8][0-9]|49[0-1])($|[^0-9])", 
  # X94x with LC.BR.P153 or previous
  "^x94[0-9]$",
  "^lc\.br\.p(0[0-9][0-9]|1[0-4][0-9]|15[0-3])($|[^0-9])", 
  # N4000 with LC.MD.P119 or previous
  "^n4000$",
  "^lc\.md\.p(0[0-9][0-9]|1[0-1][0-9])($|[^0-9])", 
  # N4050e with GO.GO.N206 or previous
  "^n4050e$",
  "^go\.go\.n([0-1][0-9][0-9]|20[0-6])($|[^0-9])", 
  # N7xxe with LC.CO.N309 or previous
  "^n7[0-9][0-9]e$",
  "^lc\.co\.n([0-2][0-9][0-9]|30[0-9])($|[^0-9])"
);

model_and_fix_vers = make_array(
  "^cs31[0-9]$", "LW41.VYL.P487", 
  "^cs41[0-9]$", "LW41.VY2.P487", 
  "^cs51[0-9]$", "LW41.VY4.P487", 
  "^cx310$", "LW41.GM2.P487", 
  "^cx410$", "LW41.GM4.P487", 
  "^cx510$", "LW41.GM7.P487", 
  "^xc2132$", "LW41.GM7.P487", 
  "^ms310$", "LW41.PRL.P487", 
  "^ms312$", "LW41.PRL.P487", 
  "^ms315$", "LW41.TL2.P487", 
  "^ms410$", "LW41.PRL.P487", 
  "^ms415$", "LW41.TL2.P487", 
  "^ms51[0-9]$", "LW41.PR2.P487", 
  "^ms610dn$", "LW41.PR2.P487", 
  "^ms610dtn$", "LW41.PR2.P487", 
  "^m1145$", "LW41.PR2.P487", 
  "^m3150dn$", "LW41.PR2.P487", 
  "^ms610de$", "LW41.PR4.P487", 
  "^ms610dte$", "LW41.PR4.P487", 
  "^m3150$", "LW41.PR4.P487", 
  "^ms71[0-9]$", "LW41.DN2.P487", 
  "^ms810n$", "LW41.DN2.P487", 
  "^ms810dn$", "LW41.DN2.P487", 
  "^ms810dtn$", "LW41.DN2.P487", 
  "^ms811$", "LW41.DN2.P487", 
  "^ms812dn$", "LW41.DN2.P487", 
  "^ms812dtn$", "LW41.DN2.P487", 
  "^m5163dn$", "LW41.DN2.P487", 
  "^ms810de$", "LW41.DN4.P487", 
  "^m5155$", "LW41.DN4.P487", 
  "^m5163$", "LW41.DN4.P487", 
  "^ms812de$", "LW41.DN7.P487", 
  "^m5170$", "LW41.DN7.P487", 
  "^ms91[0-9]$", "LW41.SA.P487", 
  "^mx310$", "LW41.SB2.P487", 
  "^mx410$", "LW41.SB4.P487", 
  "^mx510$", "LW41.SB4.P487", 
  "^mx511$", "LW41.SB4.P487", 
  "^xm1145$", "LW41.SB4.P487", 
  "^mx610$", "LW41.SB7.P487", 
  "^mx611$", "LW41.SB7.P487", 
  "^xm3150$", "LW41.SB7.P487", 
  "^mx71[0-9]$", "LW41.TU.P487", 
  "^mx81[0-9]$", "LW41.TU.P487", 
  "^xm51[0-9][0-9]$", "LW41.TU.P487", 
  "^xm71[0-9][0-9]$", "LW41.TU.P487", 
  "^mx91[0-9]$", "LW41.MG.487", 
  "^mx6500e$", "LW41.JD.487", 
  "^c746$", "LHS41.CM2.P477", 
  "^c748$", "LHS41.CM4.P477", 
  "^cs748$", "LHS41.CM4.P477", 
  "^c79[0-9]$", "LHS41.HC.P477", 
  "^cs796$", "LHS41.HC.P477", 
  "^c925$", "LHS41.HV.P477", 
  "^c95[0-9]$", "LHS41.TP.P477", 
  "^x548$", "LHS41.VK.P477", 
  "^xs548$", "LHS41.VK.P477", 
  "^x74[0-9]$", "LHS41.NY.P477", 
  "^xs748$", "LHS41.NY.P477", 
  "^x792$", "LHS41.MR.P477", 
  "^xs79[0-9]$", "LHS41.MR.P477", 
  "^x925$", "LHS41.HK.P477", 
  "^xs925$", "LHS41.HK.P477", 
  "^x95[0-9]$", "LHS41.TQ.P477", 
  "^xs95[0-9]$", "LHS41.TQ.P477", 
  "^6500e$", "LHS41.JR.P477", 
  "^c734$", "LR.SK.P697", 
  "^c736$", "LR.SKE.P695", 
  "^e46[0-9]$", "LR.LBH.P676", 
  "^t650$", "LR.JP.P685", 
  "^t652$", "LR.JP.P685", 
  "^t654$", "LR.JP.P685", 
  "^t656$", "LSJ.SJ.P045", 
  "^w85[0-9]$", "LR.JB.P648", 
  "^x46[0-9]$", "LR.BS.P699", 
  "^x65[0-9]$", "LR.MN.P701", 
  "^x73[0-9]$", "LR.FL.P699", 
  "^x86[0-9]$", "LP.SP.P701", 
  "^c54[0-9]$", "LL.AS.P537", 
  "^e26[0-9]$", "LL.LBL.P542", 
  "^e36[0-9]$", "LL.LBM.P542", 
  "^x26[0-9]$", "LL.BZ.P547", 
  "^x36[0-9]$", "LL.BZ.P547", 
  "^x54[0-9]$", "LL.EL.P547", 
  "^c52[0-9]$", "LS.FA.P153", 
  "^c53[0-9]$", "LS.SW.P072", 
  "^c77[0-9]$", "LC.CM.P054", 
  "^c78[0-9]$", "LC.IO.P190", 
  "^c92[0-9]$", "LS.TA.P155", 
  "^c93[0-9]$", "LC.JO.P096", 
  "^e45[0-9]$", "LM.SZ.P125", 
  "^t64[0-9]$", "LS.ST.P354", 
  "^w84[0-9]$", "LS.HA.P255", 
  "^x642$", "LC2.MB.P319", 
  "^x644$", "LC2.MC.P378", 
  "^x646$", "LC2.MC.P378", 
  "^x64[0-9]ef$", "LC2.TI.P330", 
  "^x77[0-9]$", "LC2.TR.P292", 
  "^x78[0-9]$", "LC2.TO.P340", 
  "^x85[0-9]$", "LC4.BE.P492", 
  "^x94[0-9]$", "LC.BR.P154", 
  "^n4000$", "Contact Lexmark", 
  "^n4050e$", "Contact Lexmark", 
  "^n7[0-9][0-9]e$", "Contact Lexmark"
);

vuln_regex = NULL;
report_fix = FALSE;

# See if detected model is in the affected list
foreach model_regex (keys(model_and_vuln_vers))
{
  if (use_model =~ model_regex)
  {
    vuln_regex = model_and_vuln_vers[model_regex];

    # Do the vercheck
    if (use_version =~ vuln_regex)
    {
      vuln = TRUE;
      report_fix = model_and_fix_vers[model_regex];
    }
    break;
  }
}

if (report_fix)
{
  if (report_verbosity > 0)
  {
    report = '\n  Model             : ' + report_model +
             '\n  Installed version : ' + report_version +
             '\n  Fixed version     : ' + report_fix +
             '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "The Lexmark printer ("+report_model+")", report_version);
