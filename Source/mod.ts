
import { setFailed , getInput } from '@actions/core'
import { parse } from 'yaml'

import {Chalk} from 'chalk';


try {

    const chalk = new Chalk({level: 2});

    console.log(chalk.rgb(200,100,50)(`Colored message`))


    class Person {

        private readonly first : string
        readonly last : string

        constructor (
            first : string ,
            last : string
        ){
            this.first = first
            this.last = last
        }
    }


    const tyrone = new Person("Tyrone", "Jones");
    const janet = new Person("Janet", "Smith");
    const maria = new Person("Maria", "Cruz");

    console.table([tyrone, janet, maria])


    console.log("Hello via Bun!");

    const yaml = getInput('Config')

    console.log('Yaml',yaml)

    const config = parse(yaml)

    console.log('Config',config)

} catch ( exception ){

    setFailed(JSON.stringify(exception,null,4))
}
