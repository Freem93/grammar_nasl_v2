#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96874);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/27 16:20:34 $");

  script_cve_id(
    "CVE-2017-3730",
    "CVE-2017-3731",
    "CVE-2017-3732"
  );
  script_bugtraq_id(
    95812,
    95813,
    95814
  );
  script_osvdb_id(
    151018,
    151019,
    151020
  );

  script_name(english:"OpenSSL 1.1.0 < 1.1.0d Multiple Vulnerabilities");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"A service running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSL running on the remote
host is 1.1.0 prior to 1.1.0d. It is, therefore, affected by multiple
vulnerabilities :

  - A NULL pointer dereference flaw exists within file
    ssl/statem/statem_clnt.c when handling parameters for
    the DHE or ECDHE key exchanges. An unauthenticated,
    remote attacker can exploit this, via specially crafted
    parameters, to cause a denial of service condition.
    (CVE-2017-3730)

  - An out-of-bounds read error exists when handling packets
    using the CHACHA20/POLY1305 or RC4-MD5 ciphers. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted truncated packets, to cause a denial
    of service condition. (CVE-2017-3731)

  - A carry propagating error exists in the x86_64
    Montgomery squaring implementation that may cause the
    BN_mod_exp() function to produce incorrect results. An
    unauthenticated, remote attacker with sufficient
    resources can exploit this to obtain sensitive
    information regarding private keys. Note that this issue
    is very similar to CVE-2015-3193. Moreover, the attacker
    would additionally need online access to an unpatched
    system using the target private key in a scenario with
    persistent DH parameters and a private key that is
    shared between multiple clients. For example, this can
    occur by default in OpenSSL DHE based SSL/TLS cipher
    suites. (CVE-2017-3732)");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20170126.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.1.0d or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'1.1.0d', min:"1.1.0", severity:SECURITY_HOLE);
