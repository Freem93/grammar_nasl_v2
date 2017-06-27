#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17765);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/02/22 19:25:29 $");

  script_cve_id("CVE-2009-0789", "CVE-2009-1377", "CVE-2009-1378", "CVE-2009-2409");
  script_bugtraq_id(34256, 35001);
  script_osvdb_id(52866, 54612, 54613, 56752);
  script_xref(name:"EDB-ID", value:"8720");

  script_name(english:"OpenSSL < 0.9.8l Multiple Vulnerabilities");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of
OpenSSL that is earlier than 0.9.8l.  As such, it may be affected by
multiple vulnerabilities :

  - A remote attacker could crash the server by sending 
    malformed ASN.1 data. This flaw only affects some 
    architectures, Win64 and other unspecified platforms. 
    (CVE-2009-0789)

  - A remote attacker could saturate the server by sending 
    a big number of 'future epoch' DTLS records. 
    (CVE-2009-1377)

  - A remote attacker could saturate the server by sending 
    duplicate DTLS records, or DTLS records with too big 
    sequence numbers. (CVE-2009-1378)

  - A remote attacker could spoof certificates by computing 
    MD2 hash collisions. (CVE-2009-2409)");
  script_set_attribute(attribute:"see_also", value:"http://voodoo-circle.sourceforge.net/sa/sa-20090326-01.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20090325.txt");
  script_set_attribute(attribute:"see_also", value:"http://voodoo-circle.sourceforge.net/sa/sa-20091012-01.html");
  script_set_attribute(attribute:"see_also", value:"http://rt.openssl.org/Ticket/Display.html?id=1930&user=guest&pass=guest");
  script_set_attribute(attribute:"see_also", value:"http://rt.openssl.org/Ticket/Display.html?id=1931&user=guest&pass=guest");
  script_set_attribute(attribute:"see_also", value:"http://cvs.openssl.org/chngview?cn=18187");
  script_set_attribute(attribute:"see_also", value:"http://cvs.openssl.org/chngview?cn=18188");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.8l or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189, 310, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/05");
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

openssl_check_version(fixed:'0.9.8l', severity:SECURITY_WARNING);
