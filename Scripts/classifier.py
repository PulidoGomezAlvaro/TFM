
from owlready2 import *
from rdflib import URIRef
import csv

onto_path.append("/Users/alvaropulidogomez/Downloads/TFM/PROTEGE")

onto = get_ontology("http://www.tfm.com/ontologies/tfm.owl").load()

matriz_riesgo_MAGERIT = {
    ('MB', 'MB'): 'MB',
    ('MB', 'B'): 'MB',
    ('MB', 'M'): 'B',
    ('MB', 'A'): 'M',
    ('MB', 'MA'): 'A',
    ('B', 'MB'): 'MB',
    ('B', 'B'): 'B',
    ('B', 'M'): 'M',
    ('B', 'A'): 'A',
    ('B', 'MA'): 'MA',
    ('M', 'MB'): 'MB',
    ('M', 'B'): 'B',
    ('M', 'M'): 'M',
    ('M', 'A'): 'A',
    ('M', 'MA'): 'MA',
    ('A', 'MB'): 'B',
    ('A', 'B'): 'M',
    ('A', 'M'): 'A',
    ('A', 'A'): 'MA',
    ('A', 'MA'): 'MA',
    ('MA', 'MB'): 'B',
    ('MA', 'B'): 'M',
    ('MA', 'M'): 'A',
    ('MA', 'A'): 'MA',
    ('MA', 'MA'): 'MA'
}
matriz_medida_MAGERIT = {
    ('1', 'MB'): 'Si',
    ('1', 'B'): 'Si',
    ('1', 'M'): 'Si',
    ('1', 'A'): 'Si',
    ('1', 'MA'): 'Si',
    ('2', 'MB'): 'No',
    ('2', 'B'): 'Si',
    ('2', 'M'): 'Si',
    ('2', 'A'): 'Si',
    ('2', 'MA'): 'Si',
    ('3', 'MB'): 'No',
    ('3', 'B'): 'No',
    ('3', 'M'): 'Si',
    ('3', 'A'): 'Si',
    ('3', 'MA'): 'Si',
    ('4', 'MB'): 'No',
    ('4', 'B'): 'No',
    ('4', 'M'): 'No',
    ('4', 'A'): 'Si',
    ('4', 'MA'): 'Si',
    ('5', 'MB'): 'No',
    ('5', 'B'): 'No',
    ('5', 'M'): 'No',
    ('5', 'A'): 'No',
    ('5', 'MA'): 'Si'
}
matriz_mitigacion_MAGERIT = {
    ('0.1', 'MB'): 'MB',
    ('0.1', 'B'): 'B',
    ('0.1', 'M'): 'M',
    ('0.1', 'A'): 'A',
    ('0.1', 'MA'): 'MA',
    ('0.2', 'MB'): 'MB',
    ('0.2', 'B'): 'B',
    ('0.2', 'M'): 'M',
    ('0.2', 'A'): 'A',
    ('0.2', 'MA'): 'A',
    ('0.3', 'MB'): 'MB',
    ('0.3', 'B'): 'B',
    ('0.3', 'M'): 'B',
    ('0.3', 'A'): 'M',
    ('0.3', 'MA'): 'A',
    ('0.4', 'MB'): 'MB',
    ('0.4', 'B'): 'B',
    ('0.4', 'M'): 'B',
    ('0.4', 'A'): 'M',
    ('0.4', 'MA'): 'M',
    ('0.5', 'MB'): 'MB',
    ('0.5', 'B'): 'MB',
    ('0.5', 'M'): 'B',
    ('0.5', 'A'): 'B',
    ('0.5', 'MA'): 'M',
    ('0.6', 'MB'): 'MB',
    ('0.6', 'B'): 'MB',
    ('0.6', 'M'): 'B',
    ('0.6', 'A'): 'B',
    ('0.6', 'MA'): 'M',
    ('0.7', 'MB'): 'MB',
    ('0.7', 'B'): 'MB',
    ('0.7', 'M'): 'MB',
    ('0.7', 'A'): 'B',
    ('0.7', 'MA'): 'M',
    ('0.8', 'MB'): 'MB',
    ('0.8', 'B'): 'MB',
    ('0.8', 'M'): 'MB',
    ('0.8', 'A'): 'B',
    ('0.8', 'MA'): 'B',
    ('0.9', 'MB'): 'MB',
    ('0.9', 'B'): 'MB',
    ('0.9', 'M'): 'MB',
    ('0.9', 'A'): 'MB',
    ('0.9', 'MA'): 'B',
    ('1', 'MB'): 'MB',
    ('1', 'B'): 'MB',
    ('1', 'M'): 'MB',
    ('1', 'A'): 'MB',
    ('1', 'MA'): 'MB'
}

with onto:

    org = onto.Organizacion(URIRef("http://www.tfm.com/ontologies/tfm.owl#Organizacion"))

    # Cargar los activos
    activos_afectados = set()  # conjunto para almacenar los activos afectados
    medidas_de_seguridad = set() #conjunto para almacenar las medidas de seguridad que entran en vigor
    protegeCategorias = {} #una medida protege estas categorias de activos
    vulnerabilidades_por_activo = {} #relaciona las vulnerabilidades que afectan a cada activo
    activos_y_medidas = {}#relaciona los activos con las medidas que los protegen
    medidas_por_activo = {}

    suma = 0
    sumaRes = 0
    riesgos = 0
    magerit = False
    cramm = False
    cramm2 = False
    
    with open('../Catalogos en uso/infoDeContexto.csv', newline='', encoding='utf-8-sig') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if row['Metodologia'] == 'ITSRM':
                itsrm = True
            elif row['Metodologia'] == 'NIST SP 800-30':
                itsrm = True
            elif row['Metodologia'] == 'ISO/IEC 27005':
                itsrm = True
            elif row['Metodologia'] == 'EBIOS':
                itsrm = True
            elif row['Metodologia'] == 'MAGERIT':
                magerit = True
            elif row['Metodologia'] == 'CRAMM Rapido':
                cramm = True      
            elif row['Metodologia'] == 'CRAMM Completo':
                cramm2 = True

            if row['Nombre']:
                org.organizacionTieneNombre.append(row['Nombre'])
            if row['ApetitoDeRiesgo']:
                org.tieneApetitoDeRiesgo.append(row['ApetitoDeRiesgo'])
                     

    with open('../Catalogos en uso/vulnerabilidades.csv', newline='', encoding='utf-8-sig') as csvfile:
        reader = csv.DictReader(csvfile)
        activos = []

        for row in reader:

            # Crear una instancia de la clase Vulnerabilidad para cada fila del CSV
            vulnerabilidad = onto.Vulnerabilidad(URIRef("http://www.tfm.com/ontologies/tfm.owl#" + row['Codigo']))

            vulnerabilidad.vulnerabilidadTieneDescripcion.append(row['Descripcion'])
            vulnerabilidad.tieneCodigo.append(row['Codigo'])
            
            # Crear una instancia de la clase Riesgo y establecer la relación con la Amenaza
            riesgo = onto.Riesgo(URIRef("http://www.tfm.com/ontologies/tfm.owl#Riesgo_"+row['Codigo']))
            riesgo.esGeneradoPor.append(vulnerabilidad)

            # Establecer el valor del data property tieneNivel del Riesgo
            if magerit or cramm2:
                vulnerabilidad.tieneProbabilidad.append(row['Probabilidad'])
                vulnerabilidad.tieneImpacto.append(row['Impacto'])
                nivel = matriz_riesgo_MAGERIT.get((row['Probabilidad'], row['Impacto']))
            elif cramm:
                vulnerabilidad.tieneProbabilidad.append(float(row['Probabilidad']))
                vulnerabilidad.tieneImpacto.append(float(row['Impacto']))
                nivel = (float(row['Probabilidad']) * float(row['Impacto']))*7/50
            else:
                vulnerabilidad.tieneProbabilidad.append(float(row['Probabilidad']))
                vulnerabilidad.tieneImpacto.append(float(row['Impacto']))
                nivel = float(row['Probabilidad']) * float(row['Impacto'])

            riesgo.tieneNivel = [nivel]


            activo = row['Activo']
            if activo not in vulnerabilidades_por_activo:
                vulnerabilidades_por_activo[activo] = []
            vulnerabilidades_por_activo[activo].append(vulnerabilidad)

            with open('../Catalogos en uso/Contramedidas.csv', newline='', encoding='utf-8-sig') as csvfile:
                reader2 = csv.DictReader(csvfile)
              
                for row2 in reader2:
                    if magerit or cramm2:
                        if row2['Activo'] == row['Activo'] and  matriz_medida_MAGERIT.get((row2['Coste'],nivel )) == 'Si' :

                            # Crea una instancia de la clase Medida con los valores correspondientes 
                            medida = onto.MedidaDeSeguridad(URIRef("http://www.tfm.com/ontologies/tfm.owl#" + row2['Descripcion']))
                            medida.medidaTieneDescripcion.append(row2['Descripcion'])
                            medida.tieneCoste.append(int(row2['Coste']))  
                            medida.tieneFactorDeMitigacion.append(float(row2['FactorDeMitigacion'])) 
                            protegeCategorias[medida] = row2['Activo']
                            if row['Activo'] not in medidas_por_activo:
                                medidas_por_activo[row['Activo']] = [medida]
                            else:
                                medidas_por_activo[row['Activo']].append(medida)

                            if row2['CategoriaMedida'] == 'Prevención':
                                medida.esPrevencion.append(True)
                            if row2['CategoriaMedida'] == 'Disuasión':
                                medida.esDisuasión.append(True)
                            if row2['CategoriaMedida'] == 'Eliminación':
                                medida.esEliminacion.append(True)
                            if row2['CategoriaMedida'] == 'DeApoyo':
                                medida.esDeApoyo.append(True)
                            if row2['CategoriaMedida'] == 'Correctiva':
                                medida.esCorrectiva.append(True)
                            if row2['CategoriaMedida'] == 'Corporativa':
                                medida.esCorporativa.append(True)
                                                                                          
                            medidas_de_seguridad.add(medida)

                        if row['Activo'] not in activos_afectados:
                            activos_afectados.add(row['Activo'])

                        if row2['Activo'] == row['Activo']:
                            for riesgo in onto.Riesgo.instances():
                                for med in medidas_de_seguridad:
                                    if row2['Descripcion'] in str(med):
                                        medidaAplica = True
                                        if row['Codigo'] in str(riesgo) and medidaAplica == True:
                                            riesgo.tieneNivelResidual = [(matriz_mitigacion_MAGERIT[(row2['FactorDeMitigacion'],riesgo.tieneNivel[0])])]
                                            riesgo.esReducidoPor.append(med)
                                            
                    # Crear instancias de los activos afectados directa o indirectamente
                        activos = {}  

                    elif cramm:
                        
                        if row2['Activo'] == row['Activo'] and float(row2['Coste']) <= (nivel/1.4):

                            # Crea una instancia de la clase Medida con los valores correspondientes 
                            medida = onto.MedidaDeSeguridad(URIRef("http://www.tfm.com/ontologies/tfm.owl#" + row2['Descripcion']))
                            medida.medidaTieneDescripcion.append(row2['Descripcion'])
                            medida.tieneCoste.append(int(row2['Coste']))  
                            medida.tieneFactorDeMitigacion.append(float(row2['FactorDeMitigacion'])) 
                            protegeCategorias[medida] = row2['Activo']

                            if row['Activo'] not in medidas_por_activo:
                                medidas_por_activo[row['Activo']] = [medida]
                            else:
                                medidas_por_activo[row['Activo']].append(medida)
                            print(medidas_por_activo[row['Activo']],'medidas por activo(row activo)')

                            if row2['CategoriaMedida'] == 'DeApoyo':
                                medida.esDeApoyo.append(True)
                            if row2['CategoriaMedida'] == 'Correctiva':
                                medida.esCorrectiva.append(True)
                            if row2['CategoriaMedida'] == 'Corporativa':
                                medida.esCorporativa.append(True)
                            medidas_de_seguridad.add(medida)

                        if row['Activo'] not in activos_afectados:
                            activos_afectados.add(row['Activo'])

                        nivel_residual = nivel
                        for medida in medidas_por_activo.get(row['Activo'], []):
                            # Calcular el nivel residual para el activo basándose en todas las medidas que se aplican a ese activo
                            nivel_residual *= (1 - medida.tieneFactorDeMitigacion[0])
                            nivel_residual = round(nivel_residual,2)
                            # Actualizar el nivel residual del riesgo asociado con el activo
                        for riesgo in onto.Riesgo.instances():
                            if row['Codigo'] in str(riesgo):
                                riesgo.tieneNivelResidual = [nivel_residual]
                                # Añadir la propiedad esReducidoPor a cada riesgo que le afecte una medida
                                for medida in medidas_por_activo.get(row['Activo'], []):
                                    riesgo.esReducidoPor.append(medida)
                                        
                        # Crear instancias de los activos afectados directa o indirectamente
                        activos = {}

                    else:
                        if row2['Activo'] == row['Activo'] and float(row2['Coste']) <= (nivel/10):

                            # Crea una instancia de la clase Medida con los valores correspondientes 
                            medida = onto.MedidaDeSeguridad(URIRef("http://www.tfm.com/ontologies/tfm.owl#" + row2['Descripcion']))
                            medida.medidaTieneDescripcion.append(row2['Descripcion'])
                            medida.tieneCoste.append(int(row2['Coste']))  
                            medida.tieneFactorDeMitigacion.append(float(row2['FactorDeMitigacion'])) 
                            protegeCategorias[medida] = row2['Activo']

                            if row['Activo'] not in medidas_por_activo:
                                medidas_por_activo[row['Activo']] = [medida]
                            else:
                                medidas_por_activo[row['Activo']].append(medida)

                            if row2['CategoriaMedida'] == 'DeApoyo':
                                medida.esDeApoyo.append(True)
                            if row2['CategoriaMedida'] == 'Correctiva':
                                medida.esCorrectiva.append(True)
                            if row2['CategoriaMedida'] == 'Corporativa':
                                medida.esCorporativa.append(True)
                            medidas_de_seguridad.add(medida)

                        if row['Activo'] not in activos_afectados:
                            activos_afectados.add(row['Activo'])

                        nivel_residual = nivel
                        for medida in medidas_por_activo.get(row['Activo'], []):
                            # Calcular el nivel residual para el activo basándose en todas las medidas que se aplican a ese activo
                            nivel_residual *= (1 - medida.tieneFactorDeMitigacion[0])
                            nivel_residual = round(nivel_residual,2)
                            # Actualizar el nivel residual del riesgo asociado con el activo
                        for riesgo in onto.Riesgo.instances():
                            if row['Codigo'] in str(riesgo):
                                riesgo.tieneNivelResidual = [nivel_residual]
                                # Añadir la propiedad esReducidoPor a cada riesgo que le afecte una medida
                                for medida in medidas_por_activo.get(row['Activo'], []):
                                    riesgo.esReducidoPor.append(medida)
                                        
                # Crear instancias de los activos afectados directa o indirectamente
                activos = {}

    with open('../Catalogos en uso/activos.csv', newline='', encoding='utf-8-sig') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            #Creo instancias de los activos y les asigno todas sus data properties
            if magerit:
                activo = row['Activo']
                activos[activo] = onto.Activo(URIRef("http://www.tfm.com/ontologies/tfm.owl#" + activo))
                activos[activo].activoTieneNombre.append(row['Activo'])
                activos[activo].tieneResponsable.append(row['Responsable'])
                activos[activo].esActivoPrincipal.append(True)
                activos[activo].perteneceALaCategoria.append(row['Categoria'])
                activos[activo].tieneValordeIntegridad.append(float(row['ValorIntegridad']))
                activos[activo].tieneValordeConfidencialidad.append(float(row['ValorConfidencialidad']))
                activos[activo].tieneValordeDisponibilidad.append(float(row['ValorDisponibilidad']))
                activos[activo].tieneValorTotal.append(float(row['ValorTotal']))

                if row['DependeDe']:
                    activos_dependientes = row['DependeDe'].split('_')
                    for activo_dependiente in activos_dependientes:
                        activos[activo_dependiente] = onto.Activo(URIRef("http://www.tfm.com/ontologies/tfm.owl#" + activo_dependiente))
                        if activo_dependiente in activos:
                            activos[activo].tieneActivoDependiente.append(activos[activo_dependiente])
                            activos[activo_dependiente].tieneActivoPrincipal.append(activos[activo])
                            activos[activo_dependiente].esActivoDependiente.append(True)
                            activos[activo_dependiente].tieneResponsable.append(row['Responsable'])
                            activos[activo_dependiente].activoTieneNombre.append(activo_dependiente)

                #si la categoria del activo se ve afectada por una vulnerabilidad, este activo se relaciona con la vulnerabilidad
                print(vulnerabilidades_por_activo,'vulnerabilidades_por_activo')
                print(activos_afectados,'activos_afectados')
                if row['Categoria'] in vulnerabilidades_por_activo and row['Categoria'] in activos_afectados:
                    print(row['Categoria'],'row Categoria')
                    for vuln in vulnerabilidades_por_activo[row['Categoria']]:
                        print(vulnerabilidades_por_activo[row['Categoria']],'vulnerabilidades_por_activo[row[Categoria]]')
                        print(activos,'activos')
                        print(activos[activo],'activos[activo]')
                        activos[activo].esVulnerableA.append(vuln)
                        print(activos_dependientes,'activos_dependientes')
                        if  not len(row['DependeDe']) == 0:
                            for act in activos_dependientes:#les pongo la propiedad a todos los activos de soporte de ese activo primario
                                activos[act].esVulnerableA.append(vuln)

                for medida in medidas_de_seguridad:
                    for activo in activos:
                            if protegeCategorias[medida] == row['Categoria'] and activo == row['Activo']:#compruebo si la medida protege ese tipo de activo y si coincide el activo especifico (PCs por ejemplo)
                                activos[activo].esProtegidoPor.append(medida)
                                activos_y_medidas[activos[activo]] = medida
                                if  not len(row['DependeDe']) == 0:
                                    for act in activos_dependientes:#les pongo la propiedad a todos los activos de soporte de ese activo primario
                                        activos[act].esProtegidoPor.append(medida)
                                        activos_y_medidas[activos[act]] = medida
            elif cramm or cramm2:
                activo = row['Activo']
                activos[activo] = onto.Activo(URIRef("http://www.tfm.com/ontologies/tfm.owl#" + activo))
                activos[activo].activoTieneNombre.append(row['Activo'])
                activos[activo].tieneResponsable.append(row['Responsable'])
                activos[activo].perteneceALaCategoria.append(row['Categoria'])
                activos[activo].tieneValordeIntegridad.append(float(row['ValorIntegridad']))
                activos[activo].tieneValordeConfidencialidad.append(float(row['ValorConfidencialidad']))
                activos[activo].tieneValordeDisponibilidad.append(float(row['ValorDisponibilidad']))
                activos[activo].tieneValorTotal.append(float(row['ValorTotal']))

                #si la categoria del activo se ve afectada por una vulnerabilidad, este activo se relaciona con la vulnerabilidad
                if row['Categoria'] in vulnerabilidades_por_activo and row['Categoria'] in activos_afectados:
                    for vuln in vulnerabilidades_por_activo[row['Categoria']]:
                        activos[activo].esVulnerableA.append(vuln)

                for medida in medidas_de_seguridad:
                    for activo in activos:
                            if protegeCategorias[medida] == row['Categoria'] and activo == row['Activo']:#compruebo si la medida protege ese tipo de activo y si coincide el activo especifico (PCs por ejemplo)
                                    activos[activo].esProtegidoPor.append(medida)
                                    activos_y_medidas[activos[activo]] = medida             
            else:

                activo = row['Activo']
                activos[activo] = onto.Activo(URIRef("http://www.tfm.com/ontologies/tfm.owl#" + activo))
                activos[activo].activoTieneNombre.append(row['Activo'])
                activos[activo].tieneResponsable.append(row['Responsable'])
                activos[activo].esActivoPrimario.append(True)
                activos[activo].perteneceALaCategoria.append(row['Categoria'])
                activos[activo].tieneValordeIntegridad.append(float(row['ValorIntegridad']))
                activos[activo].tieneValordeConfidencialidad.append(float(row['ValorConfidencialidad']))
                activos[activo].tieneValordeDisponibilidad.append(float(row['ValorDisponibilidad']))
                activos[activo].tieneValorTotal.append(row['ValorTotal'])

                if row['ActivosDeSoporte']:
                    activos_de_soporte = row['ActivosDeSoporte'].split('_')
                    for activo_de_soporte in activos_de_soporte:
                        activos[activo_de_soporte] = onto.Activo(URIRef("http://www.tfm.com/ontologies/tfm.owl#" + activo_de_soporte))
                        activos[activo_de_soporte].activoTieneNombre.append(activo_de_soporte)
                        activos[activo_de_soporte].tieneResponsable.append(row['Responsable'])
                        activos[activo_de_soporte].esActivoDeSoporte.append(True)
                        activos[activo_de_soporte].tieneActivoPrimario.append(activos[activo])
                        activos[activo].tieneActivoDeSoporte.append(activos[activo_de_soporte])
                        if activo_de_soporte in vulnerabilidades_por_activo:
                            for vuln in vulnerabilidades_por_activo[activo_de_soporte]:
                                activos[activo_de_soporte].esVulnerableA.append(vuln)
                                activos[activo].esVulnerableA.append(vuln)

                for medida in medidas_de_seguridad:
                    for activo in activos:
                            if protegeCategorias[medida] == row['Categoria'] and activo == row['Activo']:#compruebo si la medida protege ese tipo de activo y si coincide el activo especifico (PCs por ejemplo)
                                activos[activo].esProtegidoPor.append(medida)
                                activos_y_medidas[activos[activo]] = medida
                                if not len(row['ActivosDeSoporte']) == 0:
                                    for act in activos_de_soporte:#les pongo la propiedad a todos los activos de soporte de ese activo primario
                                        activos[act].esProtegidoPor.append(medida)
                                        activos_y_medidas[activos[act]] = medida   

    #Calcular el riesgo total que tiene la organizacion dependiendo de la metodologia
    for riesgo in onto.Riesgo.instances():
            if magerit or cramm2:
                if riesgo.tieneNivel[0] == 'MB' or riesgo.tieneNivel[0] == 'B':
                    riesgo.esRiesgoBajo.append(True)
                elif riesgo.tieneNivel[0] == 'M':
                    riesgo.esRiesgoMedio.append(True)
                else:
                    riesgo.esRiesgoAlto.append(True)
                riesgos = riesgos+1
                valor_riesgo = {'MB': 1, 'B': 2, 'M': 3, 'A': 4, 'MA': 5}
                suma = valor_riesgo[riesgo.tieneNivel[0]]+suma
                if len(riesgo.tieneNivelResidual) > 0:
                    sumaRes = valor_riesgo[riesgo.tieneNivelResidual[0]]+sumaRes
                    print(sumaRes,'sumaRes')

            elif cramm:
                if riesgo.tieneNivel[0] <= 2.5:
                    riesgo.esRiesgoBajo.append(True)
                elif riesgo.tieneNivel[0]  <= 5:
                    riesgo.esRiesgoMedio.append(True)
                else:
                    riesgo.esRiesgoAlto.append(True)

                suma = float(riesgo.tieneNivel[0]) + suma
                if len(riesgo.tieneNivelResidual) > 0:
                    sumaRes = float(riesgo.tieneNivelResidual[0]) + sumaRes
                riesgos = riesgos+1

            else:
                if riesgo.tieneNivel[0] <= 7:
                    riesgo.esRiesgoBajo.append(True)
                elif riesgo.tieneNivel[0]  <= 20:
                    riesgo.esRiesgoMedio.append(True)
                else:
                    riesgo.esRiesgoAlto.append(True)

                suma += float(riesgo.tieneNivel[0])
                if len(riesgo.tieneNivelResidual) > 0:
                    sumaRes += float(riesgo.tieneNivelResidual[0])
                else:
                    sumaRes += float(riesgo.tieneNivel[0])
                riesgos += 1

    #Le asigno a la organizacion el riesgo total y el riesgo residual total
    valor_nivel_riesgo = {1: 'MB', 2: 'B', 3: 'M', 4: 'A', 5: 'MA'}
    if magerit or cramm2:
        promedio_riesgo = suma / riesgos
        print(promedio_riesgo,'promedio_riesgo')
        promedio_riesgoRes = sumaRes/riesgos
        nivel_riesgo = ''
        nivel_riesgoRes = ''
        print(promedio_riesgoRes,'nivel_riesgoRes')  
        nivel_riesgoRes = valor_nivel_riesgo[1]     
        for valor, nivel in valor_nivel_riesgo.items():
            if promedio_riesgo >= valor:
                nivel_riesgo = nivel
            if promedio_riesgoRes >= valor:
                nivel_riesgoRes = nivel

        
        org.tieneRiesgoGlobal.append(nivel_riesgo)
        org.tieneRiesgoResidual.append(nivel_riesgoRes)
    else:
        nivel_riesgo = round((suma/riesgos),2)
        nivel_riesgoRes = round((sumaRes/riesgos),2)

        org.tieneRiesgoGlobal.append(nivel_riesgo)
        org.tieneRiesgoResidual.append(nivel_riesgoRes)


    #Compruebo el valor del riesgo total y del nivel de apetito de riesgo de la empresa para ver si es necesario llevar a cabo contramdedidas y calcular riesgos residuales o no
    with open('../Catalogos en uso/infoDeContexto.csv', newline='', encoding='utf-8-sig') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if magerit or cramm2:
                valor_riesgo = {'MB': 1, 'B': 2, 'M': 3, 'A': 4, 'MA': 5}
                print(valor_riesgo[row['ApetitoDeRiesgo']],'valor_riesgo')
                print(promedio_riesgo,'promedio_riesgo')
                if valor_riesgo[row['ApetitoDeRiesgo']] >= (promedio_riesgo):
                    for medida in onto.MedidaDeSeguridad.instances():
                        destroy_entity(medida)
                    for org in onto.Organizacion.instances():
                        print(org)
                        del org.tieneRiesgoResidual[0]
                    for riesgo in onto.Riesgo.instances():
                        if riesgo.tieneNivelResidual:
                            del riesgo.tieneNivelResidual[0]
            else:
                if float(row['ApetitoDeRiesgo']) >= (suma/riesgos):
                    for medida in onto.MedidaDeSeguridad.instances():
                        destroy_entity(medida)
                    for org in onto.Organizacion.instances():
                        print(org)
                        del org.tieneRiesgoResidual[0]
                    for riesgo in onto.Riesgo.instances():
                        if riesgo.tieneNivelResidual:
                            del riesgo.tieneNivelResidual[0]

        #Lógica de las amenazas: explotan una vulnerabilidad y todos los activos afectados por ella pierden valor de integridad, confidencialidad y disponibilidad
        with open('../Catalogos en uso/vulnerabilidades.csv', newline='', encoding='utf-8-sig') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                with open('../Catalogos en uso/amenazas.csv', newline='', encoding='utf-8-sig') as csvfile:
                    reader2 = csv.DictReader(csvfile)
                    for row2 in reader2:
                        if str(row['Codigo']) == str(row2['Vulnerabilidad']):
                            # Crear una instancia de la clase Amenaza y establecer la relación con la Vulnerabilidad
                            amenaza = onto.Amenaza(URIRef("http://www.tfm.com/ontologies/tfm.owl#Amenaza_"+row['Codigo']))
                            amenaza.amenazaTieneNombre.append(row2['Nombre'])
                            amenaza.amenazaTieneDescripcion.append(row2['Descripcion'])
                            if row2['Origen'] and row2['Origen'] == 'Interno':
                                amenaza.esAmenazaInterna.append(True)
                            if row2['Origen'] and row2['Origen'] == 'Externo':  
                                amenaza.esAmenazaExterna.append(True)
                            vulnerabilidad = onto.Vulnerabilidad(URIRef("http://www.tfm.com/ontologies/tfm.owl#" + row['Codigo']))
                            amenaza.explota.append(vulnerabilidad)

                            for activo in vulnerabilidad.afectaA:
                                print(activo)
                                amenaza.afectaA.append(activo)
                                if magerit or cramm2:
                                    impacto = row['Impacto']
                                    if row2['Integridad'] == '1' and  not hasattr(activo, "esActivodeSoporte") and not len(activo.tieneValordeIntegridad) == 0 :
                                        if impacto == 'MA':
                                            activo.tieneValordeIntegridad[0] = float(activo.tieneValordeIntegridad[0]) * 0.1
                                            activo.tieneValordeIntegridad[0] = round(activo.tieneValordeIntegridad[0],2)
                                        elif impacto == 'A':
                                            activo.tieneValordeIntegridad[0] = float(activo.tieneValordeIntegridad[0]) * 0.3
                                            activo.tieneValordeIntegridad[0] = round(activo.tieneValordeIntegridad[0],2)
                                        elif impacto == 'M':
                                            activo.tieneValordeIntegridad[0] = float(activo.tieneValordeIntegridad[0]) * 0.5
                                            activo.tieneValordeIntegridad[0] = round(activo.tieneValordeIntegridad[0],2)
                                        elif impacto == 'B':
                                            activo.tieneValordeIntegridad[0] = float(activo.tieneValordeIntegridad[0]) * 0.7
                                            activo.tieneValordeIntegridad[0] = round(activo.tieneValordeIntegridad[0],2)
                                        elif impacto == 'MB':
                                            activo.tieneValordeIntegridad[0] = float(activo.tieneValordeIntegridad[0]) * 0.9
                                            activo.tieneValordeIntegridad[0] = round(activo.tieneValordeIntegridad[0],2)
                                        activo.tieneValorTotal[0] = float(activo.tieneValordeIntegridad[0])+float(activo.tieneValordeConfidencialidad[0])+float(activo.tieneValordeDisponibilidad[0])
                                        activo.tieneValorTotal[0] = round(activo.tieneValorTotal[0],2)

                                    if row2['Confidencialidad'] == '1' and  not hasattr(activo, "esActivodeSoporte") and not len(activo.tieneValordeConfidencialidad) == 0:
                                        if impacto == 'MA':
                                            activo.tieneValordeConfidencialidad[0] = float(activo.tieneValordeConfidencialidad[0]) * 0.1
                                            activo.tieneValordeConfidencialidad[0] = round(activo.tieneValordeConfidencialidad[0],2)
                                        elif impacto == 'A':
                                            activo.tieneValordeConfidencialidad[0] = float(activo.tieneValordeConfidencialidad[0]) * 0.3
                                            activo.tieneValordeConfidencialidad[0] = round(activo.tieneValordeConfidencialidad[0],2)
                                        elif impacto == 'M':
                                            activo.tieneValordeConfidencialidad[0] = float(activo.tieneValordeConfidencialidad[0]) * 0.5
                                            activo.tieneValordeConfidencialidad[0] = round(activo.tieneValordeConfidencialidad[0],2)
                                        elif impacto == 'B':
                                            activo.tieneValordeConfidencialidad[0] = float(activo.tieneValordeConfidencialidad[0]) * 0.7
                                            activo.tieneValordeConfidencialidad[0] = round(activo.tieneValordeConfidencialidad[0],2)
                                        elif impacto == 'MB':
                                            activo.tieneValordeConfidencialidad[0] = float(activo.tieneValordeConfidencialidad[0]) * 0.9
                                            activo.tieneValordeConfidencialidad[0] = round(activo.tieneValordeConfidencialidad[0],2)
                                        activo.tieneValorTotal[0] = float(activo.tieneValordeIntegridad[0])+float(activo.tieneValordeConfidencialidad[0])+float(activo.tieneValordeDisponibilidad[0])
                                        activo.tieneValorTotal[0] = round(activo.tieneValorTotal[0],2)
                                    if row2['Disponibilidad'] == '1' and  not hasattr(activo, "esActivodeSoporte") and not len(activo.tieneValordeDisponibilidad) == 0:
                                        if impacto == 'MA':
                                            activo.tieneValordeDisponibilidad[0] = float(activo.tieneValordeDisponibilidad[0]) * 0.1
                                            activo.tieneValordeDisponibilidad[0] = round(activo.tieneValordeDisponibilidad[0],2)
                                        elif impacto == 'A':
                                            activo.tieneValordeDisponibilidad[0] = float(activo.tieneValordeDisponibilidad[0]) * 0.3
                                            activo.tieneValordeDisponibilidad[0] = round(activo.tieneValordeDisponibilidad[0],2)
                                        elif impacto == 'M':
                                            activo.tieneValordeDisponibilidad[0] = float(activo.tieneValordeDisponibilidad[0]) * 0.5
                                            activo.tieneValordeDisponibilidad[0] = round(activo.tieneValordeDisponibilidad[0],2)
                                        elif impacto == 'B':
                                            activo.tieneValordeDisponibilidad[0] = float(activo.tieneValordeDisponibilidad[0]) * 0.7
                                            activo.tieneValordeDisponibilidad[0] = round(activo.tieneValordeDisponibilidad[0],2)
                                        elif impacto == 'MB':
                                            activo.tieneValordeDisponibilidad[0] = float(activo.tieneValordeDisponibilidad[0]) * 0.9
                                            activo.tieneValordeDisponibilidad[0] = round(activo.tieneValordeDisponibilidad[0],2)
                                        activo.tieneValorTotal[0] = float(activo.tieneValordeIntegridad[0])+float(activo.tieneValordeConfidencialidad[0])+float(activo.tieneValordeDisponibilidad[0])
                                        activo.tieneValorTotal[0] = round(activo.tieneValorTotal[0],2)


                                else: 
                                    if row2['Integridad'] == '1' and  not hasattr(activo, "esActivodeSoporte") and not len(activo.tieneValordeIntegridad) == 0:
                                        activo.tieneValordeIntegridad[0] = (float(activo.tieneValordeIntegridad[0])*(1-(float(row['Impacto'])/10)))
                                        activo.tieneValordeIntegridad[0] = round(activo.tieneValordeIntegridad[0],2)
                                        activo.tieneValorTotal[0] = float(activo.tieneValordeIntegridad[0])+float(activo.tieneValordeConfidencialidad[0])+float(activo.tieneValordeDisponibilidad[0])
                                        activo.tieneValorTotal[0] = round(activo.tieneValorTotal[0],2)

                                    if row2['Confidencialidad'] == '1' and  not hasattr(activo, "esActivodeSoporte") and not len(activo.tieneValordeConfidencialidad) == 0:
                                        activo.tieneValordeConfidencialidad[0] = (float(activo.tieneValordeConfidencialidad[0])*(1-(float(row['Impacto'])/10)))
                                        activo.tieneValordeConfidencialidad[0] = round(activo.tieneValordeConfidencialidad[0],2)
                                        activo.tieneValorTotal[0] = float(activo.tieneValordeIntegridad[0])+float(activo.tieneValordeConfidencialidad[0])+float(activo.tieneValordeDisponibilidad[0])
                                        activo.tieneValorTotal[0] = round(activo.tieneValorTotal[0],2)

                                    if row2['Disponibilidad'] == '1' and  not hasattr(activo, "esActivodeSoporte") and not len(activo.tieneValordeIntegridad) == 0:
                                        activo.tieneValordeDisponibilidad[0] = (float(activo.tieneValordeDisponibilidad[0])*(1-(float(row['Impacto'])/10)))
                                        activo.tieneValordeDisponibilidad[0] = round(activo.tieneValordeDisponibilidad[0],2)
                                        activo.tieneValorTotal[0] = float(activo.tieneValordeIntegridad[0])+float(activo.tieneValordeConfidencialidad[0])+float(activo.tieneValordeDisponibilidad[0])
                                        activo.tieneValorTotal[0] = round(activo.tieneValorTotal[0],2)



    # Ejecutar el razonador y guardar la ontología
    sync_reasoner()
    onto.save("/Users/alvaropulidogomez/Downloads/TFM/PROTEGE/tfm2.owl")
