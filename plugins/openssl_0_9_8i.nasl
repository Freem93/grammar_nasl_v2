#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17761);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/02/22 19:25:29 $");

  script_cve_id("CVE-2009-1386");
  script_bugtraq_id(35174);
  script_osvdb_id(55073);
  script_xref(name:"EDB-ID", value:"8873");

  script_name(english:"OpenSSL < 0.9.8i Denial of Service");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of 
OpenSSL that is earlier than 0.9.8i. 

A remote attacker can crash the server by sending a DTLS
ChangeCipherSpec packet before the ClientHello.");
  script_set_attribute(attribute:"see_also", value:"http://cvs.openssl.org/chngview?cn=17369");
  script_set_attribute(attribute:"see_also", value:"http://rt.openssl.org/Ticket/Display.html?id=1679&user=guest&pass=guest");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.8i or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/15");
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

openssl_check_version(fixed:'0.9.8i', severity:SECURITY_WARNING);
