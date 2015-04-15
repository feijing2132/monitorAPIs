// dllmain.h : Declaration of module class.

class CdllModule : public ATL::CAtlDllModuleT< CdllModule >
{
public :
	DECLARE_LIBID(LIBID_dllLib)
	DECLARE_REGISTRY_APPID_RESOURCEID(IDR_DLL, "{8129C964-DEF7-41A7-BEA9-E33974E291BB}")
};

extern class CdllModule _AtlModule;
