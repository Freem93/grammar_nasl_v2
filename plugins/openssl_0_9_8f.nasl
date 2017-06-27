#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17760);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/02/22 19:25:29 $");

  script_cve_id("CVE-2007-3108", "CVE-2007-4995");
  script_bugtraq_id(25163, 26055);
  script_osvdb_id(37055, 37895);
  script_xref(name:"CERT", value:"724968");

  script_name(english:"OpenSSL < 0.9.8f Multiple Vulnerabilities");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of
OpenSSL that is earlier than 0.9.8f.  As such, it is affected by the
following vulnerabilities :

  - A local attacker could perform a side-channel attack 
    against the Montgomery multiplication code and retrieve 
    RSA private keys. Note that this has not been exploited 
    outside a laboratory environment. (CVE-2007-3108)

  - A remote attacker could execute arbitrary code by 
    exploiting an off-by-one error in the DTLS 
    implementation. (CVE-2007-4995)");
  script_set_attribute(attribute:"see_also", value:"http://cvs.openssl.org/chngview?cn=16275");
  script_set_attribute(attribute:"see_also", value:"http://openssl.org/news/patch-CVE-2007-3108.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/RGII-74KLP3");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20071012.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.8f or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'0.9.8f', severity:SECURITY_HOLE);
