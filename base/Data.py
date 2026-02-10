from vcgencmd import vcgencmd
def temperature():
    ''' Gets the current temperature of a system '''
    a = vcgencmd.Vcgencmd()
    return {'error': False, 'result': a.measure_temp()}

def mem_reloc() -> dict:
    a = vcgencmd.Vcgencmd()
    return {'error': False, 'result': a.mem_reloc_stats()}
