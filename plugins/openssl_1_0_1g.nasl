#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73404);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2014-0076", "CVE-2014-0160");
  script_bugtraq_id(66363, 66690);
  script_osvdb_id(104810, 105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");

  script_name(english:"OpenSSL 1.0.1 < 1.0.1g Multiple Vulnerabilities (Heartbleed)");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:"The remote service may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote web server uses a version of
OpenSSL 1.0.1 prior to 1.0.1g. The OpenSSL library is, therefore,
reportedly affected by the following vulnerabilities :

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    could allow nonce disclosure via the 'FLUSH+RELOAD'
    cache side-channel attack. (CVE-2014-0076)

  - An out-of-bounds read error, known as the 'Heartbleed
    Bug', exists related to handling TLS heartbeat
    extensions that could allow an attacker to obtain
    sensitive information such as primary key material,
    secondary key material and other protected content.
    (CVE-2014-0160)");
  script_set_attribute(attribute:"see_also", value:"http://heartbleed.com/");
  script_set_attribute(attribute:"see_also", value:"http://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#2014-0076");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  # Release announce
  script_set_attribute(attribute:"see_also", value:"http://www.mail-archive.com/openssl-announce@openssl.org/msg00131.html");
  # CVE-2014-0160 git commit
  # http://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=96db902
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4229df1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL 1.0.1g or later.

Alternatively, recompile OpenSSL with the '-DOPENSSL_NO_HEARTBEATS'
flag to disable the vulnerable functionality.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'1.0.1g', min:"1.0.1", severity:SECURITY_HOLE);
