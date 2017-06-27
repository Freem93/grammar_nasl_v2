#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93718);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/28 21:52:55 $");

  script_cve_id(
   "CVE-2015-7744",
   "CVE-2016-0610",
   "CVE-2016-3471"
  );
  script_bugtraq_id(
    81198,
    81245,
    91913
  );
  script_osvdb_id(
    130734,
    130735,
    130782,
    130783,
    130859,
    131920,
    132114,
    133182,
    133188,
    141885
  );

  script_name(english:"MariaDB 10.1.x < 10.1.9 Multiple Vulnerabilities");
  script_summary(english:"Checks the MariaDB version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 10.1.x prior to
10.1.9. It is, therefore, affected by the following vulnerabilities :

  - A flaw exists in the encryption subcomponent due to a
    failure to properly handle faults associated with the
    Chinese Remainder Theorem (CRT) process when allowing
    ephemeral key exchange without low memory optimizations
    on a server. An unauthenticated, remote attacker can
    exploit this to disclose private RSA keys by capturing
    TLS handshakes. (CVE-2015-7744)

  - An unspecified flaw exists in the InnoDB subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service. (CVE-2016-0610)

  - An unspecified flaw exists in the Option subcomponent
    that allows an authenticated, remote attacker to gain
    elevated privileges. (CVE-2016-3471)

  - A flaw exists in the check_fk_parent_table_access()
    function in sql_parse.cc that is triggered when
    performing database name conversions. An authenticated,
    remote attacker can exploit this to crash the database,
    resulting in a denial of service. (VulnDB 130734)

  - A flaw exists in the gis_field_options_read() function
    in field.cc that is triggered during the handling of the  
    GIS feature. An authenticated, remote attacker can
    exploit this to crash the database, resulting in a
    denial of service. (VulnDB 130735)

  - An unspecified flaw exists in the init_read_record_idx()
    function that is triggered when handling errors. An
    authenticated, remote attacker can exploit this to cause
    a denial of service. (VulnDB 130782)

  - An overflow condition exists in the XMLColumns()
    function in tabxml.cpp due to improper validation of
    user-supplied input. An authenticated, remote attacker
    can exploit this to cause a buffer overflow, resulting
    in a denial of service condition or the execution of
    arbitrary code. (VulnDB 130783)

  - An unspecified flaw exists that is triggered when
    handling UPDATE queries with JOIN. An authenticated,
    remote attacker can exploit this to crash the database,
    resulting in a denial of service. (VulnDB 130859)

  - An unspecified flaw exists that is triggered during the
    handling of 'View' or 'Derived' fields. An
    authenticated, remote attacker can exploit this to crash
    the database, resulting in a denial of service.
    (VulnDB 131920)

  - A flaw exists in the row_merge_sort() function that is
    triggered when handling FT-index creation. An
    authenticated, remote attacker can exploit this to crash
    the database, resulting in a denial of service.
    (VulnDB 132114)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-1019-release-notes/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-1019-changelog/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.1.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB', fixed:'10.1.9-MariaDB', min:'10.1', severity:SECURITY_HOLE);
