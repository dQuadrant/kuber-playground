import { createRouter, createWebHistory } from 'vue-router'
import Editor from '@/components/Editor.vue'

console.log(import.meta.env.BASE_URL)

const pathregex  = new RegExp('.*')
const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      // @ts-ignore
      path: '/',
      name: 'home',
      component: Editor
    },
    {
      path: '/kuber',
      name: 'kuber',
      component: Editor
    },
    {
      path: '/kuber-playground',
      name: 'playground',
      component: Editor
    }
  ]
})

export default router
