#TRUSTED b305ffaf1b1a787d2079900879099bbd14924213c43e95c219f6322f70541dab69b399e6c7ab2417cd58f8cedf9dfe294d0c59549095733e21a1920b7038304a8be95f5894182f676067369522198485d33455b87a2c5782753fb0e4f663f1baf8259f4de07dc700350b48b3470335f1ea500503427604825c8c64b704844d109d6a76f67a83b681122ad13500540bb27d1740656d458e452c8f8e996cb9229c3817f026fac3e1f6dfabbec2ed5bbcb7cc07826970a0844e07620fa2cde19e9821788d76b9fcf471aeaaef84746bfe7feca8ab241a2bd925fe1b0066ba2489a015b2a2b7e398fc1c46eba7f52971dc06915f20ae79571f2dbdae40f86ccead3024495c467114d78349613c889d5536c01e78482070364b533936d1e553fec56bde9f7e2104cb22619d5fe4e1ba5032e9eb7b770218ffc727f1f18f3db58bd9aa9fe2bff38cb002d1bbf9db9467d8552447f8ebddb696b542ebee6a9d6259aa7aa9f0be3c4575c67d6f588974e611ea5326bd48c498dbc9f00217063976ff8cab6f2d044d72e10f43430da03cbc48e5fc941e20737afea55e4297bdfd8d5f4b332a6cb0f0b9d75e795e638d683267c58497b9915b132bc88171638a05afb9a593b56914772dc0e55af273b42c095bfd571538f853da43ac8ae9a25ab187b401e0bbbd306af79cfe42e394461e50f613bfa350a79683389928fdc6bef253658ca8
#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@


include( 'compat.inc' );

if(description)
{
  script_id(57861);
  script_version ("1.0");

  script_name(english:"IBM iSeries Credentials");
  script_summary(english:"Sets iSeries Credentials");

  script_set_attribute(
    attribute:'synopsis',
    value:'Sets the IBM iSeries Credentials settings.'
  );

  script_set_attribute(  attribute:'description',  value:
"This script just sets global variables (iSeries login and password)
and does not perform any security check."  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_attribute(
    attribute:"risk_factor", 
    value:"None"
  );
 script_set_attribute(attribute:"plugin_publication_date", value: "2012/02/08");
 script_set_attribute(attribute:"plugin_modification_date", value: "2012/02/08");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
  script_category(ACT_SETTINGS);

  script_add_preference(name: "Login :", type: "entry", value: "");
  script_add_preference(name: "Password :", type: "password", value: "");

  exit(0);
}

login = script_get_preference("Login :");
pass = script_get_preference("Password :");
if ( strlen(login) > 0 && strlen(pass) > 0 )
{
 set_kb_item(name:"Secret/iSeries/Login", value:login);
 set_kb_item(name:"Secret/iSeries/Password", value:pass);
}
else exit(0, "No iSeries login or password provided");
