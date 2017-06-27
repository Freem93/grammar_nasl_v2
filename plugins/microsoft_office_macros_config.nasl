#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92361);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"Microsoft Office Macros Configuration");
  script_summary(english:"Report Office macros configuration information.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to collect and report Office macro configuration data
for active accounts on the remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to collect Office macro configuration information
for active accounts on the remote Windows host and generate a report
as a CSV attachment.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Incident Response");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("charset_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("csv_generator.inc");

exit(0, "This plugin is temporarily disabled");

get_kb_item_or_exit("SMB/Registry/Enumerated");

registry_init();

#HKU\<SID>\Software\Microsoft\Office
hku_keys = get_hku_keys(key:"\Software\Microsoft\Office", reg_init:FALSE);
if (isnull(hku_keys))
{
   close_registry();
   audit(AUDIT_REG_FAIL);
}
if (max_index(keys(hku_keys)) == 0)
{
  close_registry();
  exit(0, "Microsoft Office security settings not found.");
}

# Recurse all Office subkeys finding versions.
office_versions = make_array();

foreach sid(keys(hku_keys))
{
   foreach key(hku_keys[sid])
   {
      if (key =~ "\d+\.\d+")
      {
        if (isnull(office_versions[sid]))
        {
          office_versions[sid] = make_list();
        }
        office_versions[sid][max_index(office_versions[sid])]= 'Software\\Microsoft\\Office\\' + key;
      }
   }
}

# Recurse all subkeys in office_versions looking for Security
hku = registry_hive_connect(hive:HKEY_USERS);
if (isnull(hku))
{
  close_registry();
  audit(AUDIT_REG_FAIL);
}

office_security = make_array();
foreach sid(keys(office_versions))
{
  foreach version(office_versions[sid])
  {
    app_list = get_registry_subkeys(handle:hku, key:sid + '\\' + version);
    foreach app(app_list)
    {
      app_keys = get_registry_subkeys(handle:hku, key:sid + '\\' + version + '\\' + app);
      foreach key(app_keys)
      {
        if (tolower(key) == "security")
        {
          if (isnull(office_security[sid]))
          {
            office_security[sid] = make_list();
          }
          office_security[sid][max_index(office_security[sid])] = version + '\\' + app + '\\' + key;
        }
      }
    }
  }
}

# Pull VBAWarnings from all Security subkeys
office_vbawarnings = make_list();
i = 0;
foreach sid(keys(office_security))
{
  office_vbawarnings[i] = make_array();
  foreach security(office_security[sid])
  {
    vbawarnings = get_registry_value(handle:hku, item:sid + '\\' + security + '\\VBAWarnings');
    if (!isnull(vbawarnings))
    {
      office_vbawarnings[i]["user_sid"] = sid;
      office_vbawarnings[i]["key"] = security + '\\VBAWarnings';
      office_vbawarnings[i]["value"] = vbawarnings;
      ++i;
    }
  }
}

# Recruse all Trusted Locations
office_trusted_locations = make_list();
i = 0;
foreach sid(keys(office_security))
{
  office_trusted_locations[i] = make_array();
  foreach security(office_security[sid])
  {
    trusted_locations = get_registry_subkeys(handle:hku, key:sid + '\\' + security + '\\Trusted Locations');
    foreach location(trusted_locations)
    {
      values = get_reg_name_value_table(handle:hku, key:sid + '\\' + security + '\\Trusted Locations\\' + location);
      if (!isnull(values))
      {
        office_trusted_locations[i] = values;
        office_trusted_locations[i]["user_sid"] = sid;
        office_trusted_locations[i]["key"] = security + '\\Trusted Locations\\' + location;
        ++i;
      }
    }
  }
}

# Recurse all Trusted Documents
office_trusted_documents = make_list();
office_purge = make_list();
doc_count = 0;
purge_count = 0;
foreach sid(keys(office_security))
{
  foreach security(office_security[sid])
  {
    lastpurgetime = get_registry_value(handle:hku, item:sid + '\\' + security + '\\Trusted Documents\\LastPurgeTime');
    if (!isnull(lastpurgetime))
    {
      office_purge[purge_count] = make_array();
      office_purge[purge_count]["user_sid"] = sid;
      office_purge[purge_count]["key"] = security + '\\Trusted Documents\\LastPurgeTime';
      office_purge[purge_count]["value"] = lastpurgetime;
      ++purge_count;
    }

    trust_records = get_reg_name_value_table(handle:hku, key:sid + '\\' + security + '\\Trusted Documents\\TrustRecords');
    if (!isnull(trust_records))
    {
      foreach record(keys(trust_records))
      {
        office_trusted_documents[doc_count] = make_array();
        office_trusted_documents[doc_count]["user_sid"] = sid;
        office_trusted_documents[doc_count]["key"] = security + '\\Trusted Documents\\TrustRecords';
        office_trusted_documents[doc_count]["record"] = record;
        office_trusted_documents[doc_count]["value"] = toupper(hexstr(trust_records[record]));
        ++doc_count;
      }
    }
  }
}

RegCloseKey(handle:hku);
close_registry();

attachments = make_list();
i = 0;

if (max_index(office_vbawarnings) > 0)
{
  office_vbawarnings_header = header_from_list(list:make_list("user_sid", "key", "value"));
  csv = generate_csv(header:office_vbawarnings_header, data:office_vbawarnings);
  attachments[i] = make_array();
  attachments[i]["name"] = "office_vbawarnings.csv";
  attachments[i]["value"] = csv;
  attachments[i]["type"] = "text/csv";
  ++i;
}

if (max_index(office_trusted_locations) > 0)
{
  office_trusted_locations_header = header_from_list(list:make_list("user_sid", "key"));
  office_trusted_locations_header = header_from_data(header:office_trusted_locations_header, data:office_trusted_locations);
  csv = generate_csv(header:office_trusted_locations_header, data:office_trusted_locations);
  attachments[i] = make_array();
  attachments[i]["name"] = "office_trusted_locations.csv";
  attachments[i]["value"] = csv;
  attachments[i]["type"] = "text/csv";
  ++i;
}

if (max_index(office_purge) > 0)
{
  office_purge_header = header_from_list(list:make_list("user_sid", "key", "value"));
  csv = generate_csv(header:office_purge_header, data:office_purge);
  attachments[i] = make_array();
  attachments[i]["name"] = "office_lastpurgetime.csv";
  attachments[i]["value"] = csv;
  attachments[i]["type"] = "text/csv";
  ++i;
}

if (max_index(office_trusted_documents) > 0)
{
  office_trusted_documents_header = header_from_list(list:make_list("user_sid", "key", "record", "value"));
  csv = generate_csv(header:office_trusted_documents_header, data:office_trusted_documents);
  attachments[i] = make_array();
  attachments[i]["name"] = "office_trusted_records.csv";
  attachments[i]["value"] = csv;
  attachments[i]["type"] = "text/csv";
  ++i;
}

if (max_index(attachments) > 0)
{
  report = 'Office macros information attached.';
  security_report_with_attachments(port:0, level:0, extra:report, attachments:attachments);
}
else
{
  exit(0, "Microsoft Office security settings not found.");
}
