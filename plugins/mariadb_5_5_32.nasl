#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72373);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/09/28 21:23:45 $");

  script_cve_id(
    "CVE-2013-1861",
    "CVE-2013-3783",
    "CVE-2013-3793",
    "CVE-2013-3802",
    "CVE-2013-3804",
    "CVE-2013-3809",
    "CVE-2013-3812"
  );
  script_bugtraq_id(
    58511,
    61210,
    61244,
    61249,
    61260,
    61264,
    61272,
    62085
  );
  script_osvdb_id(
    91415,
    91416,
    95322,
    95323,
    95325,
    95328,
    95332,
    95336,
    97781,
    97782,
    97783,
    97784,
    97785,
    97786,
    97787,
    97788,
    97789,
    97790,
    97791,
    97792,
    97793,
    97794,
    97795,
    97796,
    97797,
    97798,
    97799
  );

  script_name(english:"MariaDB 5.5 < 5.5.32 Multiple Vulnerabilities");
  script_summary(english:"Checks MariaDB version");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB 5.5 running on the remote host is a version
prior to 5.5.32. It is, therefore, potentially affected by the
following vulnerabilities :

  - Errors exist related to the following subcomponents :
    Audit Log, Data Manipulation Language, Full Text Search,
    GIS, Server Optimizer, Server Parser and
    Server Replication. (CVE-2013-1861, CVE-2013-3783,
    CVE-2013-3793, CVE-2013-3802, CVE-2013-3804,
    CVE-2013-3809, CVE-2013-3812)

  - Errors exist in the files 'sql/item_func.cc',
    'sql/item_sum.cc', 'sql/item_timefunc.cc',
    'sql/opt_range.cc', 'sql/sql_derived.cc',
    'sql/sql_insert.cc', 'sql/sql_select.cc',
    'sql/sql_table.cc', 'sql/table.cc' and
    'storage/innobase/mem/mem0mem.c' that could allow
    denial of service attacks. (VulnDB 97781, 97782, 97783,
    97785, 97787, 97790, 97792, 97793, 97794, 97796, 97798,
    97799)

  - Errors exist in the functions or methods 'CONVERT_TZ
    Item_func_min_max::get_date', 'my_decimal2decimal',
    'setup_ref_array' and 'st_select_lex::nest_last_join'
    that could allow denial of service attacks. (VulnDB
    97784, 97786, 97788, 97795, 97797, 97799)

  - A buffer overflow error exists in the file
    'sql/opt_range.cc' in the function
    'QUICK_GROUP_MIN_MAX_SELECT::next_min' that could allow
    denial of service attacks and possibly arbitrary code
    execution (VulnDB 97789)

  - An unspecified issue exists in the file 'dbug/dbug.c'
    in the macro 'str_to_buf' that has an unspecified
    impact. (VulnDB 97791)");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb-5532-changelog/");
  script_set_attribute(attribute:"solution", value:"Upgrade to MariaDB version 5.5.32 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB', fixed:'5.5.32-MariaDB', min:'5.5', severity:SECURITY_HOLE);
