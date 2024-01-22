// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func alitesting() {

	// kubeconfig := flag.String("kubeconfig", filepath.Join(os.Getenv("HOME"), ".kube", "config"), "path to kubeconfig file")
	kubeconfig := "/Users/alisonburgess/.kube/config"
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	/*
		apiGroups, err := clientset.Discovery().ServerGroups()
		if err != nil {
			panic(err.Error())
		}

		fmt.Printf("API Groups:\n")
		for _, group := range apiGroups.Groups {
			fmt.Printf(" - Group: %s, Versions: %s\n", group.Name, group.Versions)
		}
	*/
	check, err := clientset.Discovery().ServerVersion()
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("Server Version:\n")
	fmt.Printf(" - Version: %s\n", check.GitVersion)

	// Example: List Pods in the "default" namespace
	namespace := "default"
	// pods, err := clientset.CoreV1().Pods("default").List(context.TODO(), metav1.ListOptions{})
	pods, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("Pods in namespaces:\n")
	for _, pod := range pods.Items {
		fmt.Printf(" - %s\n", pod.GetName())
	}
}

func main() {
	alitesting()
}
