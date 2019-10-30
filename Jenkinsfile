@Library('jenkins-joylib@v1.0.2') _

pipeline {

    agent {
        label joyCommonLabels(image_ver: '19.1.0')
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '45'))
        timestamps()
    }

    stages {
        stage('check') {
            steps{
                sh('make check')
            }
        }
        // TODO: Switch to convention based make target
        stage('test') {
            steps {
                sh('cargo test --lib')
            }
        }
        stage('build agent and upload') {
            steps { 
                sh('''
set -o errexit
set -o pipefail

export ENGBLD_BITS_UPLOAD_IMGAPI=true
make print-BRANCH print-STAMP all release publish bits-upload''')
            }
        }
    }

    post {
        always {
            joyMattermostNotification()
        }
    }

}
