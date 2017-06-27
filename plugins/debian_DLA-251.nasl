#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-251-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84297);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/09/12 13:37:17 $");

  script_cve_id("CVE-2012-6531", "CVE-2012-6532", "CVE-2014-2681", "CVE-2014-2682", "CVE-2014-2683", "CVE-2014-2684", "CVE-2014-2685", "CVE-2014-4914", "CVE-2014-8088", "CVE-2014-8089", "CVE-2015-3154");
  script_bugtraq_id(57977, 66358, 68031, 70011, 70378, 74561);
  script_osvdb_id(104286, 104330, 104331, 105276, 108047, 111466, 111721, 121821);

  script_name(english:"Debian DLA-251-2 : zendframework regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The previous zendframework upload incorrectly fixes CVE-2015-3154,
causing a regression. This update corrects this problem. Thanks to
&#x415;&#x432;&#x433;&#x435;&#x43D;&#x438;&#x439;
&#x421;&#x43C;&#x43E;&#x43B;&#x438;&#x43D; (Evgeny Smolin)
<esmolin@inbox.ru>.

CVE-2012-6531

P&aacute;draic Brady identified a weakness to handle the
SimpleXMLElement zendframework class, allowing to remote attackers to
read arbitrary files or create TCP connections via an XML external
entity (XXE) injection attack.

CVE-2012-6532

P&aacute;draic Brady found that remote attackers could cause a denial
of service by CPU consumption, via recursive or circular references
through an XML entity expansion (XEE) attack.

CVE-2014-2681

Lukas Reschke reported a lack of protection against XML External
Entity injection attacks in some functions. This fix extends the
incomplete one from CVE-2012-5657.

CVE-2014-2682

Lukas Reschke reported a failure to consider that the
libxml_disable_entity_loader setting is shared among threads in the
PHP-FPM case. This fix extends the incomplete one from CVE-2012-5657.

CVE-2014-2683

Lukas Reschke reported a lack of protection against XML Entity
Expansion attacks in some functions. This fix extends the incomplete
one from CVE-2012-6532.

CVE-2014-2684

Christian Mainka and Vladislav Mladenov from the Ruhr-University
Bochum reported an error in the consumer's verify method that lead to
acceptance of wrongly sourced tokens.

CVE-2014-2685

Christian Mainka and Vladislav Mladenov from the Ruhr-University
Bochum reported a specification violation in which signing of a single
parameter is incorrectly considered sufficient.

CVE-2014-4914

Cassiano Dal Pizzol discovered that the implementation of the ORDER BY
SQL statement in Zend_Db_Select contains a potential SQL injection
when the query string passed contains parentheses.

CVE-2014-8088

Yury Dyachenko at Positive Research Center identified potential XML
eXternal Entity injection vectors due to insecure usage of PHP's DOM
extension.

CVE-2014-8089

Jonas Sandstr&ouml;m discovered a SQL injection vector when manually
quoting value for sqlsrv extension, using null byte.

CVE-2015-3154

Filippo Tessarotto and Maks3w reported potential CRLF injection
attacks in mail and HTTP headers.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/06/msg00019.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/zendframework"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected zendframework, and zendframework-bin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zendframework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zendframework-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"6.0", prefix:"zendframework", reference:"1.10.6-1squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"zendframework-bin", reference:"1.10.6-1squeeze4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
