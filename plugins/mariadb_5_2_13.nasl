#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63148);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/10/27 15:03:54 $");

  script_cve_id("CVE-2012-5611"); # CVE-2012-5579 is a duplicate of this and shouldn't be used
  script_bugtraq_id(56769);
  script_osvdb_id(88060, 88066);
  script_xref(name:"EDB-ID", value:"23075");

  script_name(english:"MariaDB 5.2 < 5.2.13 Buffer Overflow");
  script_summary(english:"Checks MariaDB version");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB 5.2 running on the remote host is prior to
5.2.13. It is, therefore, affected by a buffer overflow vulnerability.
A remote, authenticated attacker could exploit this to execute
arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Dec/4");
  script_set_attribute(attribute:"see_also", value:"https://kb.askmonty.org/en/mariadb-5213-release-notes/");
  script_set_attribute(attribute:"solution", value:"Upgrade to MariaDB version 5.2.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB', fixed:'5.2.13-MariaDB', min:'5.2', severity:SECURITY_WARNING);
