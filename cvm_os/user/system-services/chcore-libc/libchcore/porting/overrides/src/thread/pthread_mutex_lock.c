#include "pthread_impl.h"
#include <chcore/syscall.h>

int __pthread_mutex_lock(pthread_mutex_t *m)
{
	int cur_prio = 0, r;
	bool set_ceil = false;

	if ((m->_m_type&15) == PTHREAD_MUTEX_NORMAL
	    && !a_cas(&m->_m_lock, 0, EBUSY))
		r = 0;
	else
		r = __pthread_mutex_timedlock(m, 0);

	return r;
}

weak_alias(__pthread_mutex_lock, pthread_mutex_lock);
