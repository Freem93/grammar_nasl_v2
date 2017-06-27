#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17749);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/02/22 19:25:29 $");

  script_cve_id("CVE-2003-0851");
  script_bugtraq_id(8970);
  script_osvdb_id(2765);
  script_xref(name:"CERT", value:"412478");

  script_name(english:"OpenSSL < 0.9.6l Denial of Service");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of
OpenSSL that is earlier than 0.9.6l. 

A remote attacker can trigger a denial of service by using an invalid
client certificate.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20031104.txt");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=106796246511667&w=2");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.6l or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/11/04");
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

openssl_check_version(fixed:'0.9.6l', severity:SECURITY_WARNING);
