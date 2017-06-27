#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90888);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/10/03 14:18:40 $");

  script_cve_id("CVE-2016-2108");
  script_bugtraq_id(89752);
  script_osvdb_id(137900);

  script_name(english:"OpenSSL 1.0.1 < 1.0.1o ASN.1 Encoder Negative Zero Value Handling RCE");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
OpenSSL 1.0.1 prior to 1.0.1o. It is, therefore, affected by a remote
code execution vulnerability in the ASN.1 encoder due to an underflow
condition that occurs when attempting to encode the value zero
represented as a negative integer. An unauthenticated, remote attacker
can exploit this to corrupt memory, resulting in the execution of
arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160503.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/cl101.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.1o or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'1.0.1o', min:"1.0.1", severity:SECURITY_HOLE);
