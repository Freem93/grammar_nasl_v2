#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17767);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/22 19:25:29 $");

  script_cve_id("CVE-2010-2939");
  script_bugtraq_id(42306);
  script_osvdb_id(66946);
  script_xref(name:"GLSA", value:"201110-01");

  # http://www.openssl.org/news/changelog.html
  # http://www.gentoo.org/security/en/glsa/glsa-201110-01.xml 
  script_name(english:"OpenSSL < 0.9.8p / 1.0.0e Double Free Vulnerability");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSL layer is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of 
OpenSSL that is earlier than 0.9.8p / 1.0.0e. 

A remote attacker could crash client software when using ECDH.  The
impact of this vulnerability is not clear; arbitrary code could be run
too. 

Note that OpenSSL changelog only reports a fix for 0.9.8p.  1.0.0a is
definitely vulnerable.  Gentoo reports a fix for 1.0.0e but it covers
other flaws.NVD reports 0.9.7 as vulnerable too but does not give any
fixed version.");
  script_set_attribute(attribute:"see_also", value:"http://www.mail-archive.com/openssl-dev@openssl.org/msg28049.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.8p / 1.0.0e or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/06");
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

openssl_check_version(fixed:make_list('0.9.8p', '1.0.0e'), severity:SECURITY_WARNING);
