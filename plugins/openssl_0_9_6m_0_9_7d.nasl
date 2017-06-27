#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17750);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/02/22 19:25:29 $");

  script_cve_id("CVE-2004-0079", "CVE-2004-0112");
  script_bugtraq_id(9899);
  script_osvdb_id(4316, 4317);
  script_xref(name:"CERT", value:"484726");

  script_name(english:"OpenSSL < 0.9.6m / 0.9.7d Denial of Service");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of 
OpenSSL that is earlier than 0.9.6m or 0.9.7d. 

A remote attacker can crash the server by sending an overly long
Kerberos ticket or a crafted SSL/TLS handshake.");
  script_set_attribute(attribute:"see_also", value:"http://www.us-cert.gov/cas/techalerts/TA04-078A.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20040317.txt");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=107953412903636&w=2");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.6m / 0.9.7d or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/03/17");
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

openssl_check_version(fixed:make_list('0.9.6m', '0.9.7d'), severity:SECURITY_WARNING);
