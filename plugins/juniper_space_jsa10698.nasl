#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91778);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/29 16:45:58 $");

  script_cve_id(
    "CVE-2013-2249",
    "CVE-2013-5908",
    "CVE-2013-6438",
    "CVE-2014-0098",
    "CVE-2014-0429",
    "CVE-2014-0453",
    "CVE-2014-0456",
    "CVE-2014-0460",
    "CVE-2014-1568",
    "CVE-2014-6478",
    "CVE-2014-6491",
    "CVE-2014-6494",
    "CVE-2014-6495",
    "CVE-2014-6496",
    "CVE-2014-6500",
    "CVE-2014-6559",
    "CVE-2015-0501",
    "CVE-2015-0975",
    "CVE-2015-2620",
    "CVE-2015-3209",
    "CVE-2015-7753"
  );
  script_bugtraq_id(
    61379,
    64896,
    66303,
    66856,
    66877,
    66914,
    66916,
    70116,
    70444,
    70469,
    70478,
    70487,
    70489,
    70496,
    70497,
    74070,
    75123,
    75837
  );
  script_osvdb_id(
    95521,
    102078,
    104579,
    104580,
    105866,
    105868,
    105889,
    105897,
    112036,
    113253,
    113254,
    113259,
    113260,
    113261,
    113262,
    113263,
    117831,
    120743,
    123147,
    124749,
    136722,
    136723,
    136724
  );
  script_xref(name:"JSA", value:"JSA10698");

  script_name(english:"Juniper Junos Space < 15.1R1 Multiple Vulnerabilities (JSA10698)");
  script_summary(english:"Checks the version of Junos Space.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Junos
Space running on the remote device is prior to 15.1R1. It is,
therefore, affected by multiple vulnerabilities :

  - An error exists within the Apache 'mod_session_dbd'
    module, related to save operations for a session, due to
    a failure to consider the dirty flag and to require a
    new session ID. An unauthenticated, remote attacker can
    exploit this to have an unspecified impact.
    (CVE-2013-2249)

  - An unspecified flaw exists in the MySQL Server component
    related to error handling that allows a remote attacker
    to cause a denial of service condition. (CVE-2013-5908)

  - A flaw exists within the Apache 'mod_dav' module that is
    caused when tracking the length of CDATA that has
    leading white space. An unauthenticated, remote attacker
    can exploit this, via a specially crafted DAV WRITE
    request, to cause the service to stop responding.
    (CVE-2013-6438)

  - A flaw exists within the Apache 'mod_log_config' module
    that is caused when logging a cookie that has an
    unassigned value. An unauthenticated, remote attacker
    can exploit this, via a specially crafted request, to
    cause the service to crash. (CVE-2014-0098)

  - A flaw exists, related to pixel manipulation, in the
    2D component in the Oracle Java runtime that allows an
    unauthenticated, remote attacker to impact availability,
    confidentiality, and integrity. (CVE-2014-0429)

  - A flaw exists, related to PKCS#1 unpadding, in the
    Security component in the Oracle Java runtime that
    allows an unauthenticated, remote attacker to gain
    knowledge of timing information, which is intended to
    be protected by encryption. (CVE-2014-0453)

  - A race condition exists, related to array copying, in
    the Hotspot component in the Oracle Java runtime that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2014-0456)

  - A flaw exists in the JNDI component in the Oracle Java
    runtime due to missing randomization of query IDs. An
    unauthenticated, remote attacker can exploit this to
    conduct spoofing attacks. (CVE-2014-0460)

  - A flaw exists in the Mozilla Network Security Services
    (NSS) library, which is due to lenient parsing of ASN.1
    values involved in a signature and can lead to the
    forgery of RSA signatures, such as SSL certificates.
    (CVE-2014-1568)

  - An unspecified flaw exists in the MySQL Server component
    related to the CLIENT:SSL:yaSSL subcomponent that allows
    a remote attacker to impact integrity. (CVE-2014-6478)

  - Multiple unspecified flaws exist in the MySQL Server
    component related to the SERVER:SSL:yaSSL subcomponent
    that allow a remote attacker to impact confidentiality,
    integrity, and availability. (CVE-2014-6491,
    CVE-2014-6500)

  - Multiple unspecified flaws exist in the MySQL Server
    component related to the CLIENT:SSL:yaSSL subcomponent
    that allow a remote attacker to cause a denial of
    service condition. (CVE-2014-6494, CVE-2014-6495,
    CVE-2014-6496)

  - An unspecified flaw exists in the MySQL Server component
    related to the C API SSL Certificate Handling
    subcomponent that allows a remote attacker to disclose
    potentially sensitive information. (CVE-2014-6559)

  - An unspecified flaw exists in the MySQL Server component
    related to the Server:Compiling subcomponent that allows
    an authenticated, remote attacker to cause a denial of
    service condition. (CVE-2015-0501)

  - An XML external entity (XXE) injection vulnerability
    exists in OpenNMS due to the Castor component accepting
    XML external entities from exception messages. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted XML data in a RTC post, to access
    local files. (CVE-2015-0975)

  - An unspecified flaw exists in the MySQL Server component
    related to the Server:Security:Privileges subcomponent
    that allows a remote attacker to disclose potentially
    sensitive information. (CVE-2015-2620)

  - A heap buffer overflow condition exists in QEMU in the
    pcnet_transmit() function within file hw/net/pcnet.c
    due to improper validation of user-supplied input when
    handling multi-TMD packets with a length above 4096
    bytes. An unauthenticated, remote attacker can exploit
    this, via specially crafted packets, to gain elevated
    privileges from guest to host. (CVE-2015-3209)

  - Multiple cross-site scripting (XSS), SQL injection, and
    command injection vulnerabilities exist in Junos Space
    that allow an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2015-7753)");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10698&actp=search
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22595a74");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Junos Space version 15.1R1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_space");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Junos_Space/version");

  exit(0);
}

include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Junos_Space/version');

check_junos_space(ver:ver, fix:'15.1R1', severity:SECURITY_HOLE, xss:TRUE, xsrf:TRUE, sqli:TRUE);
