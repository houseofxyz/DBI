#include "stdafx.h"
#include <fstream>
#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"
using namespace std;

static void event_exit(void);
static void wrap_malloc_pre(void *wrapcxt, OUT void **user_data);
static void wrap_malloc_post(void *wrapcxt, void *user_data);
static void wrap_free_pre(void *wrapcxt, OUT void **user_data);

ofstream LogFile;
#define MALLOC_ROUTINE_NAME "malloc"
#define FREE_ROUTINE_NAME "free"

static void module_load_event(void *drcontext, const module_data_t *mod, bool loaded)
{
	app_pc towrap = (app_pc)dr_get_proc_address(mod->handle, MALLOC_ROUTINE_NAME);
	if (towrap != NULL)
	{
		bool ok = drwrap_wrap(towrap, wrap_malloc_pre, wrap_malloc_post);

		if (!ok)
		{
			dr_fprintf(STDERR, "[-] Could not wrap 'malloc': already wrapped?\n");
			DR_ASSERT(ok);
		}
	}

	towrap = (app_pc)dr_get_proc_address(mod->handle, FREE_ROUTINE_NAME);
	if (towrap != NULL)
	{
		bool ok = drwrap_wrap(towrap, wrap_free_pre, NULL);

		if (!ok)
		{
			dr_fprintf(STDERR, "[-] Could not wrap 'free': already wrapped?\n");
			DR_ASSERT(ok);
		}
	}
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
	LogFile.open("memprofile.out");

	dr_set_client_name("DynamoRIO Sample Client 'wrap'", "http://dynamorio.org/issues");
	dr_log(NULL, LOG_ALL, 1, "Client 'wrap' initializing\n");

	if (dr_is_notify_on()) 
	{
		dr_enable_console_printing();
		dr_fprintf(STDERR, "[*] Client wrap is running\n");
	}

	drmgr_init();
	drwrap_init();
	dr_register_exit_event(event_exit);
	drmgr_register_module_load_event(module_load_event);
}

static void event_exit(void)
{
	drwrap_exit();
	drmgr_exit();
}

static void wrap_malloc_pre(void *wrapcxt, OUT void **user_data)
{
	/* malloc(size) or HeapAlloc(heap, flags, size) */
	//size_t sz = (size_t)drwrap_get_arg(wrapcxt, 2); // HeapAlloc
	size_t sz = (size_t)drwrap_get_arg(wrapcxt, 0); // malloc

	LogFile << "[*] malloc(" << dec << sz << ")"; // log the malloc size
}

static void wrap_malloc_post(void *wrapcxt, void *user_data)
{
	int actual_read = (int)(ptr_int_t)drwrap_get_retval(wrapcxt);
	LogFile << "\t\t= 0x" << hex << actual_read << endl;
}

static void wrap_free_pre(void *wrapcxt, OUT void **user_data)
{
	int addr = (int)drwrap_get_arg(wrapcxt, 0);
	LogFile << "[*] free(0x" << hex << addr << ")" << endl;
}
