#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71862);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/01/09 00:43:20 $");

  script_cve_id("CVE-2013-2162");
  script_bugtraq_id(60424);
  script_osvdb_id(94076);
  script_xref(name:"DSA", value:"2818");
  script_xref(name:"USN", value:"1909-1");

  script_name(english:"MySQL debian.cnf Plaintext Credential Disclosure");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server may be affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is 5.5.x prior to
5.5.33.  It is, therefore, potentially affected by a race condition in
the post-installation script of the MySQL server package
(mysql-server-5.5.postinst) that creates the configuration file
'/etc/mysql/debian.cnf' with world-readable permissions before
restricting the permissions.  This allows local users to read the file
and obtain credentials for the privileged 'debian-sys-maint' user.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=711600");
  script_set_attribute(attribute:"see_also", value:"http://security-tracker.debian.org/tracker/CVE-2013-2162");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2013/q2/519");
  script_set_attribute(attribute:"solution", value:
"Upgrade the MySQL server package to 5.5.33 or later on Debian / 5.5.32
or later on Ubuntu.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/08");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"Databases");

  script_dependencies("mysql_version.nasl", "os_fingerprint.nasl");
  script_require_keys("Settings/PCI_DSS");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("mysql_version.inc");

if (!get_kb_item("Settings/PCI_DSS")) audit(AUDIT_PCI);

os = get_kb_item_or_exit("Host/OS");
if ("ubuntu" >< tolower(os)) fixed_ver = "5.5.32";
else if ("debian" >< tolower(os)) fixed_ver = "5.5.33";
else audit(AUDIT_OS_NOT, "Debian or Ubuntu");

mysql_check_version(fixed:fixed_ver, min:'5.5', severity:SECURITY_NOTE);
