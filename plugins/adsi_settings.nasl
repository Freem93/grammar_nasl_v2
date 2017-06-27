#TRUSTED 04ac28e63a756fbe96a05bf8aab6cd105d02cd7b4fd06660e0cb22a072300b996590b4e9ad70fa488474140a52d86cc362bf95725225f064537c3cd7cad8b3197fd983978a16a9b5ab01b5e6d40c2a824b9c7dd000d2df4ca847de4ee78412bd53b4c7b07f1c9d1d77cb1ea5b3028248120baf969545e4a869eb8e2df03e2f69cd76468cb147df460aa6d595d445663027f3e4a7f995f0cc26b6b34f6276fb3a4b013af1975a3315bfae5fc68f652f177552fd96f4af9fbc88ffbd4ebc31d46789df6df15e78cbb0be4a0583a02ccbc2ed285f2448fd7e023b11d9007426c736c428fc795876b7f78f0a016a7f22dd013934a7d4f6f21cc4323fad746646f3a1f4ef36e4281e80001cd9838b9b1865716ba2e77794bdec836f16d7710e5c81c65eb51014dc6dc3130645b8bcb4231941c2cf4abe1ebd105261d452748a12340940de958e9b75a1e224b8abb7fa79650047b4d919533bf027278f9a81f78450765d76916a2c56fd56c8e828a40f5636ce7ce0755879b437613044b5bc302cb580f865869a02d1ada9349f9b440e5cf35b74a3f04019e9154b0c828f72b35ca7175cdc26e878b239906939406a5234d24eda31506cc829198ca4386347ed34ff61985bf0c102c4b80af1a964f1bab9ba72fad7752b8f82769f5221104ba137ff2da70aec9e5d1b05a3bbf6754b06dc51b3906b37a91de85eacfaf3a48c1c3c883a
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(60024);
  script_version ("1.2");

  script_name(english:"ADSI Settings");
  script_summary(english:"ADSI settings parameters.");

  script_set_attribute(attribute:"synopsis", value:"Set the ADSI query parameters for plugins using ADSI.");
  script_set_attribute(attribute:"description", value:"Gather and store the ADSI parameters
to be used in other plugins.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/06");
  script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/30");
  script_set_attribute(attribute: "plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");
  script_family(english:"Settings");

  script_add_preference(name:"Domain Controller : ", type:"entry", value:"");
  script_add_preference(name:"Domain : ", type:"entry", value:"");
  script_add_preference(name:"Domain Username : ", type:"entry",    value:"");
  script_add_preference(name:"Domain Password : ", type:"password", value:"");

  for (i=2; i<=5; i++)
  {
    script_add_preference(name:"Domain Controller "+i+": ", type:"entry", value:"");
    script_add_preference(name:"Domain "+i+": ", type:"entry", value:"");
    script_add_preference(name:"Domain Username "+i+": ", type:"entry",    value:"");
    script_add_preference(name:"Domain Password "+i+": ", type:"password", value:"");
  }

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");


host      = script_get_preference("Domain Controller : ");
domain    = script_get_preference("Domain : ");
username  = script_get_preference("Domain Username : ");
password  = script_get_preference("Domain Password : ");
if (!username && !password && !host && !domain) 
  exit(0, "ADSI settings are not set.");
else if (!username || !password || !host || !domain)
  exit(1, "One or more settings are set but not all settings are set.");

set_kb_item(name:"adsi/host/0" , value:host );
set_kb_item(name:"adsi/domain/0" , value:domain );
set_kb_item(name:"Secret/adsi/username/0" , value:username );
set_kb_item(name:"Secret/adsi/password/0" , value:password );

n = 1;

for (i=2; i<=5; i++)
{
  # Get the preference values
  host      = script_get_preference("Domain Controller "+i+": ");
  domain    = script_get_preference("Domain "+i+": ");
  username  = script_get_preference("Domain Username "+i+": ");
  password  = script_get_preference("Domain Password "+i+": ");
  if (!username || !password || !host || !domain) continue;

  set_kb_item(name:"adsi/host/"+n+"" , value:host );
  set_kb_item(name:"adsi/domain/"+n+"" , value:domain );
  set_kb_item(name:"Secret/adsi/username/"+n+"" , value:username );
  set_kb_item(name:"Secret/adsi/password/"+n+"" , value:password );
  n++;
}
